import uuid from 'uuid/v4';
import {
  __,
  append,
  assoc,
  chain,
  concat,
  dissoc,
  equals,
  filter,
  find as RamdaFind,
  flatten,
  fromPairs,
  groupBy,
  head,
  includes,
  isEmpty,
  isNil,
  join,
  last,
  map,
  mapObjIndexed,
  mergeAll,
  mergeRight,
  pipe,
  pluck,
  tail,
  toPairs,
  uniq,
  uniqBy
} from 'ramda';
import moment from 'moment';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn-client';
import conf, { logger } from '../config/conf';
import { buildPagination, fillTimeSeries, randomKey } from './utils';
import { isInversed } from './graknRoles';
import {
  elBulk,
  elDeleteInstanceIds,
  elLoadByGraknId,
  elLoadById,
  elLoadByStixId,
  elPaginate,
  elRemoveRelationConnection,
  elUpdate,
  forceNoCache,
  INDEX_STIX_ENTITIES,
  INDEX_STIX_OBSERVABLE,
  INDEX_STIX_RELATIONS
} from './elasticSearch';

// region global variables
const dateFormat = 'YYYY-MM-DDTHH:mm:ss';
const GraknString = 'String';
const GraknDate = 'Date';

export const TYPE_OPENCTI_INTERNAL = 'Internal';
export const TYPE_STIX_DOMAIN = 'Stix-Domain';
export const TYPE_STIX_DOMAIN_ENTITY = 'Stix-Domain-Entity';
export const TYPE_STIX_OBSERVABLE = 'Stix-Observable';
export const TYPE_STIX_OBSERVABLE_DATA = 'Stix-Observable-Data';
export const TYPE_STIX_RELATION = 'stix_relation';
export const TYPE_RELATION_EMBEDDED = 'relation_embedded';
export const TYPE_STIX_RELATION_EMBEDDED = 'stix_relation_embedded';
export const inferIndexFromConceptTypes = types => {
  // Observable index
  if (includes(TYPE_STIX_OBSERVABLE, types)) return INDEX_STIX_OBSERVABLE;
  if (includes(TYPE_STIX_OBSERVABLE_DATA, types)) return INDEX_STIX_OBSERVABLE;
  // Relation index
  if (includes(TYPE_STIX_RELATION, types)) return INDEX_STIX_RELATIONS;
  if (includes(TYPE_STIX_RELATION_EMBEDDED, types)) return INDEX_STIX_RELATIONS;
  if (includes(TYPE_RELATION_EMBEDDED, types)) return INDEX_STIX_RELATIONS;
  // Everything else in entities index
  return INDEX_STIX_ENTITIES;
};

export const now = () => {
  // eslint-disable-next-line prettier/prettier
  return moment().utc().toISOString();
};
export const graknNow = () => {
  // eslint-disable-next-line prettier/prettier
  return moment().utc().format(dateFormat); // Format that accept grakn
};
export const prepareDate = date => {
  // eslint-disable-next-line prettier/prettier
  return moment(date).utc().format(dateFormat);
};
export const sinceNowInMinutes = lastModified => {
  const utc = moment().utc();
  const diff = utc.diff(moment(lastModified));
  const duration = moment.duration(diff);
  return Math.floor(duration.asMinutes());
};
export const yearFormat = date => moment(date).format('YYYY');
export const monthFormat = date => moment(date).format('YYYY-MM');
export const dayFormat = date => moment(date).format('YYYY-MM-DD');
export const escape = chars => {
  const toEscape = chars && typeof chars === 'string';
  if (toEscape) {
    return chars
      .replace(/\\/g, '\\\\')
      .replace(/;/g, '\\;')
      .replace(/,/g, '\\,');
  }
  return chars;
};
export const escapeString = s => (s ? s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') : '');

// Attributes key that can contains multiple values.
export const multipleAttributes = ['stix_label', 'alias', 'grant', 'platform', 'required_permission'];
export const statsDateAttributes = ['first_seen', 'last_seen', 'published', 'expiration'];
// endregion

// region client
const client = new Grakn(`${conf.get('grakn:hostname')}:${conf.get('grakn:port')}`);
let session = null;
// endregion

// region basic commands
const closeTx = async gTx => {
  try {
    if (gTx.tx.isOpen()) {
      await gTx.tx.close();
    }
  } catch (err) {
    logger.error('[GRAKN] CloseReadTx error > ', err);
  }
};
const takeReadTx = async (retry = false) => {
  if (session === null) {
    session = await client.session('grakn');
  }
  try {
    const tx = await session.transaction().read();
    return { session, tx };
  } catch (err) {
    logger.error('[GRAKN] TakeReadTx error > ', err);
    await session.close();
    if (retry === false) {
      session = null;
      return takeReadTx(true);
    }
    return null;
  }
};
const executeRead = async executeFunction => {
  const rTx = await takeReadTx();
  try {
    const result = await executeFunction(rTx);
    await closeTx(rTx);
    return result;
  } catch (err) {
    await closeTx(rTx);
    logger.error('[GRAKN] executeRead error > ', err);
    throw err;
  }
};

const takeWriteTx = async (retry = false) => {
  if (session === null) {
    session = await client.session('grakn');
  }
  try {
    const tx = await session.transaction().write();
    return { session, tx };
  } catch (err) {
    logger.error('[GRAKN] TakeWriteTx error > ', err);
    if (retry === false) {
      session = null;
      return takeWriteTx(true);
    }
    return null;
  }
};
const commitWriteTx = async wTx => {
  try {
    await wTx.tx.commit();
  } catch (err) {
    logger.error('[GRAKN] CommitWriteTx error > ', err);
  }
};
export const executeWrite = async executeFunction => {
  const wTx = await takeWriteTx();
  try {
    const result = await executeFunction(wTx);
    await commitWriteTx(wTx);
    return result;
  } catch (err) {
    await closeTx(wTx);
    logger.error('[GRAKN] executeWrite error > ', err);
    throw err;
  }
};
export const write = async query => {
  const wTx = await takeWriteTx();
  try {
    await wTx.tx.query(query);
    await commitWriteTx(wTx);
  } catch (err) {
    logger.error('[GRAKN] Write error > ', err);
  } finally {
    await closeTx(wTx);
  }
};

export const graknIsAlive = async () => {
  try {
    // Just try to take a read transaction
    await executeRead(() => {});
  } catch (e) {
    logger.error(`[GRAKN] Seems down`);
    throw new Error('Grakn seems down');
  }
};
export const getGraknVersion = async () => {
  // It seems that Grakn server does not expose its version yet:
  // https://github.com/graknlabs/client-nodejs/issues/47
  return '1.5.9';
};

/**
 * Recursive fetch of every types of a concept
 * @param concept the element
 * @param currentType the current type
 * @param acc the recursive accumulator
 * @returns {Promise<Array>}
 */
export const conceptTypes = async (concept, currentType = null, acc = []) => {
  if (currentType === null) {
    const conceptType = await concept.type();
    const conceptLabel = await conceptType.label();
    acc.push(conceptLabel);
    return conceptTypes(concept, conceptType, acc);
  }
  const parentType = await currentType.sup();
  if (parentType === null) return acc;
  const conceptLabel = await parentType.label();
  if (conceptLabel === 'entity' || conceptLabel === 'relation') return acc;
  acc.push(conceptLabel);
  return conceptTypes(concept, parentType, acc);
};

/**
 * Extract all vars from a grakn query
 * @param query
 */
const extractQueryVars = query => {
  return uniq(map(m => m.replace('$', ''), query.match(/\$[a-z_]+/gi)));
};
// endregion

// region stable functions
/**
 * Query and get attribute values
 * @param type
 * @returns {{edges: *}}
 */
export const queryAttributeValues = async type => {
  return executeRead(async rTx => {
    const query = `match $x isa ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValues > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answers = await iterator.collect();
    const result = await Promise.all(
      answers.map(async answer => {
        const attribute = answer.map().get('x');
        const attributeType = await attribute.type();
        const value = await attribute.value();
        const attributeTypeLabel = await attributeType.label();
        const replacedValue = value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        return {
          node: {
            id: attribute.id,
            type: attributeTypeLabel,
            value: replacedValue
          }
        };
      })
    );
    return buildPagination(5000, 0, result, 5000);
  });
};

export const attributeExists = async attributeLabel => {
  return executeRead(async rTx => {
    const checkQuery = `match $x sub ${attributeLabel}; get;`;
    logger.debug(`[GRAKN - infer: false] attributeExists > ${checkQuery}`);
    await rTx.tx.query(checkQuery);
    return true;
  }).catch(() => false);
};

/**
 * Query and get attribute values
 * @param id
 * @returns {{edges: *}}
 */
export const queryAttributeValueById = async id => {
  return executeRead(async rTx => {
    const query = `match $x id ${escape(id)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValueById > ${query}`);
    const iterator = await rTx.tx.query(query);
    const answer = await iterator.next();
    const attribute = answer.map().get('x');
    const attributeType = await attribute.type();
    const value = await attribute.value();
    const attributeTypeLabel = await attributeType.label();
    const replacedValue = value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    return {
      id: attribute.id,
      type: attributeTypeLabel,
      value: replacedValue
    };
  });
};

/**
 * Grakn generic function to delete an instance (and orphan relationships)
 * @param id
 * @returns {Promise<any[] | never>}
 */
export const deleteAttributeById = async id => {
  return executeWrite(async wTx => {
    const query = `match $x id ${escape(id)}; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteAttributeById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    return id;
  });
};

const conceptOpts = { relationsMap: new Map() };
/**
 * Load any grakn instance with internal grakn ID.
 * @param concept the concept to get attributes from
 * @param relationsMap
 * @param noCache
 * @returns {Promise}
 */
const loadConcept = async (concept, { relationsMap, noCache = false } = conceptOpts) => {
  const { id } = concept;
  const conceptType = concept.baseType;
  const types = await conceptTypes(concept);
  const index = inferIndexFromConceptTypes(types);
  // 01. Return the data in elastic if not explicitly asked in grakn
  // Very useful for getting every entities through relation query.
  if (forceNoCache() && noCache === false) {
    const conceptFromCache = await elLoadByGraknId(id, [index]);
    if (!conceptFromCache) {
      logger.warn(`[GRAKN] Cache warning: ${id} should be available in cache`);
    } else {
      return conceptFromCache;
    }
  }
  // 02. If not found continue the process.
  logger.debug(`[GRAKN - infer: false] getAttributes > ${head(types)} ${id}`);
  const attributesIterator = await concept.attributes();
  const attributes = await attributesIterator.collect();
  const attributesPromises = attributes.map(async attribute => {
    const attributeType = await attribute.type();
    const attributeLabel = await attributeType.label();
    return {
      dataType: await attributeType.dataType(),
      label: attributeLabel,
      value: await attribute.value()
    };
  });
  return Promise.all(attributesPromises)
    .then(attributesData => {
      const transform = pipe(
        map(attribute => {
          let transformedVal = attribute.value;
          const { dataType, label } = attribute;
          if (dataType === GraknDate) {
            transformedVal = moment(attribute.value)
              .utc()
              .toISOString();
          } else if (dataType === GraknString) {
            transformedVal = attribute.value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
          }
          return { [label]: transformedVal };
        }), // Extract values
        chain(toPairs), // Convert to pairs for grouping
        groupBy(head), // Group by key
        map(pluck(1)), // Remove grouping boilerplate
        mapObjIndexed((num, key, obj) =>
          // eslint-disable-next-line no-nested-ternary
          Array.isArray(obj[key]) && !includes(key, multipleAttributes)
            ? head(obj[key])
            : head(obj[key]) && head(obj[key]) !== ''
            ? obj[key]
            : []
        ) // Remove extra list then contains only 1 element
      )(attributesData);
      return pipe(
        assoc('id', transform.internal_id_key),
        assoc('grakn_id', concept.id),
        assoc('parent_types', types),
        assoc('index_version', '1.0')
      )(transform);
    })
    .then(async entityData => {
      if (conceptType !== 'RELATION') return entityData;
      const isInferredPromise = concept.isInferred();
      const rolePlayers = await concept.rolePlayersMap();
      const roleEntries = Array.from(rolePlayers.entries()); // Array.from(rolePlayers.entries()).flat();
      const rolesPromises = Promise.all(
        map(async roleItem => {
          // eslint-disable-next-line prettier/prettier
          const roleId = last(roleItem).values().next().value.id;
          const conceptFromMap = relationsMap.get(roleId);
          return conceptFromMap
            ? head(roleItem)
                .label()
                .then(async roleLabel => {
                  return {
                    [`${conceptFromMap.entity}Id`]: roleId,
                    [`${conceptFromMap.entity}Role`]: roleLabel,
                    [`${conceptFromMap.entity}Types`]: conceptFromMap.types,
                    [conceptFromMap.entity]: null // With be use lazily
                  };
                })
            : {};
        }, roleEntries)
      );
      // Wait for all promises before building the result
      return Promise.all([isInferredPromise, rolesPromises]).then(([isInferred, roles]) => {
        return pipe(
          assoc('id', isInferred ? uuid() : entityData.id),
          assoc('inferred', isInferred),
          assoc('entity_type', entityData.entity_type || TYPE_RELATION_EMBEDDED),
          assoc('relationship_type', head(types)),
          mergeRight(mergeAll(roles))
        )(entityData);
      });
    })
    .then(globalObject => {
      // 01. First fix the direction of the relation
      // When fetching the info, we cant know the source access
      const isInv = isInversed(globalObject.relationship_type, globalObject.fromRole);
      const fixedRel = pipe(
        assoc('fromId', isInv ? globalObject.toId : globalObject.fromId),
        assoc('fromRole', isInv ? globalObject.toRole : globalObject.fromRole),
        assoc('toId', isInv ? globalObject.fromId : globalObject.toId),
        assoc('toRole', isInv ? globalObject.fromRole : globalObject.toRole)
      )(globalObject);
      // 02. Then change the id if relation is inferred
      if (globalObject.inferred) {
        const { fromId, fromRole, toId, toRole } = fixedRel;
        const type = globalObject.relationship_type;
        const pattern = `{ $rel(${fromRole}: $from, ${toRole}: $to) isa ${type}; $from id ${fromId}; $to id ${toId}; };`;
        return assoc('id', Buffer.from(pattern).toString('base64'), globalObject);
      }
      return globalObject;
    });
};

const findOpts = { infer: false, noCache: false };
/**
 * Query and get entities or relations
 * @param query
 * @param entities
 * @param infer if the query add inferences
 * @param noCache force to not use elastic
 * @param uniqueKey the result element to test for unicity (grakn_id)
 * @returns {Promise}
 */
export const find = async (query, entities, { uniqueKey, infer, noCache } = findOpts) => {
  // Remove empty values from entities
  const plainEntities = filter(e => !isEmpty(e) && !isNil(e), entities);
  return executeRead(async rTx => {
    const conceptQueryVars = extractQueryVars(query);
    logger.debug(`[GRAKN - infer: ${infer}] Find > ${query}`);
    const iterator = await rTx.tx.query(query, { infer });
    // 01. Get every concepts to fetch (unique)
    const answers = await iterator.collect();
    if (answers.length === 0) return [];
    // 02. Query concepts and rebind the data
    const queryConcepts = await Promise.all(
      map(async answer => {
        // Create a map useful for relation roles binding
        const queryVarsToConcepts = await Promise.all(
          conceptQueryVars.map(async entity => {
            const concept = answer.map().get(entity);
            if (concept.baseType === 'ATTRIBUTE') return undefined; // If specific attributes are used for filtering, ordering, ...
            const types = await conceptTypes(concept);
            return { id: concept.id, data: { concept, entity, types } };
          })
        );
        const conceptsIndex = filter(e => e, queryVarsToConcepts);
        const fetchingConceptsPairs = map(x => [x.id, x.data], conceptsIndex);
        const relationsMap = new Map(fetchingConceptsPairs);
        // Fetch every concepts of the answer
        const requestedConcepts = filter(r => includes(r.data.entity, entities), conceptsIndex);
        return map(t => {
          const { concept } = t.data;
          return { id: concept.id, concept, relationsMap };
        }, requestedConcepts);
      }, answers)
    );
    // 03. Fetch every unique concepts
    const uniqConceptsLoading = pipe(
      flatten,
      uniqBy(e => e.id),
      map(l => loadConcept(l.concept, { relationsMap: l.relationsMap, noCache }))
    )(queryConcepts);
    const resolvedConcepts = await Promise.all(uniqConceptsLoading);
    // 04. Create map from concepts
    const conceptCache = new Map(map(c => [c.grakn_id, c], resolvedConcepts));
    // 05. Bind all row to data entities
    const result = answers.map(answer => {
      const dataPerEntities = plainEntities.map(entity => {
        const concept = answer.map().get(entity);
        const conceptData = conceptCache.get(concept.id);
        return [entity, conceptData];
      });
      return fromPairs(dataPerEntities);
    });
    // 06. Filter every relation in double
    // Grakn can respond with twice the relations (browse in 2 directions)
    const uniqFilter = uniqueKey || head(entities);
    return uniqBy(u => u[uniqFilter].grakn_id, result);
  });
};
/**
 * Query and get entities of the first row
 * @param query
 * @param entities
 * @param infer
 * @param noCache
 * @returns {Promise<any[] | never>}
 */
export const load = async (query, entities, { infer, noCache } = findOpts) => {
  const data = await find(query, entities, { infer, noCache });
  return head(data);
};

// Reindex functions
export const indexElements = async (elements, retry = 0) => {
  // 01. Bulk the indexing of row elements
  const body = elements.flatMap(doc => [
    { index: { _index: inferIndexFromConceptTypes(doc.parent_types), _id: doc.grakn_id } },
    doc
  ]);
  await elBulk({ refresh: true, body });
  // 02. If relation, generate impacts for from and to sides
  const impactedEntities = pipe(
    filter(e => e.relationship_type !== undefined),
    map(e => {
      const relationId = e.id;
      const relationshipType = e.relationship_type;
      return [
        { from: e.fromId, relationshipType, to: e.toId, relationId },
        { from: e.toId, relationshipType, to: e.fromId, relationId }
      ];
    }),
    flatten,
    groupBy(i => i.from)
  )(elements);
  const elementsToUpdate = await Promise.all(
    // For each from, generate the
    map(async entityGraknId => {
      const entity = await elLoadByGraknId(entityGraknId);
      const targets = impactedEntities[entityGraknId];
      // Build document fields to update ( per relation type )
      // membership: [{internal_id_key: xxxx, relation_id_key: xxxx}]
      const targetsByRelation = groupBy(i => i.relationshipType, targets);
      const targetsElements = await Promise.all(
        map(async relType => {
          const data = targetsByRelation[relType];
          const resolvedData = await Promise.all(
            map(async d => {
              const resolvedTarget = await elLoadByGraknId(d.to);
              return { internal_id_key: resolvedTarget.internal_id_key, relation_id_key: d.relationId };
            }, data)
          );
          return { relation: relType, elements: resolvedData };
        }, Object.keys(targetsByRelation))
      );
      // Create params and scripted update
      const params = {};
      const sources = map(t => {
        const createIfNotExist = `if (ctx._source['${t.relation}'] == null) ctx._source['${t.relation}'] = [];`;
        const addAllElements = `ctx._source['${t.relation}'].addAll(params['${t.relation}'])`;
        return `${createIfNotExist} ${addAllElements}`;
      }, targetsElements);
      const source = sources.length > 1 ? join(';', sources) : `${head(sources)};`;
      for (let index = 0; index < targetsElements.length; index += 1) {
        const targetElement = targetsElements[index];
        params[targetElement.relation] = targetElement.elements;
      }
      // eslint-disable-next-line no-underscore-dangle
      return { _index: entity._index, id: entityGraknId, data: { script: { source, params } } };
    }, Object.keys(impactedEntities))
  );
  const bodyUpdate = elementsToUpdate.flatMap(doc => [
    // eslint-disable-next-line no-underscore-dangle
    { update: { _index: doc._index, _id: doc.id, retry_on_conflict: retry } },
    doc.data
  ]);
  if (bodyUpdate.length > 0) {
    await elBulk({ refresh: true, body: bodyUpdate });
  }
  return elements.length;
};
export const reindexByQuery = async (query, entities) => {
  const elements = await find(query, entities, { infer: false, noCache: true });
  // Get all inner elements
  const innerElements = pipe(
    map(entity => elements.map(e => e[entity])),
    flatten
  )(entities);
  return indexElements(innerElements);
};
export const reindexByAttribute = (type, value) => {
  const eType = escape(type);
  const eVal = escapeString(value);
  const readQuery = `match $x isa entity, has ${eType} $a; $a "${eVal}"; get;`;
  logger.debug(`[GRAKN - infer: false] attributeUpdate > ${readQuery}`);
  return reindexByQuery(readQuery, ['x']);
};

/**
 * Load any grakn instance with OpenCTI internal ID.
 * @param id element id to get
 * @returns {Promise}
 */
// ENTITIES
export const loadEntityById = async id => {
  if (!forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadById(id);
    if (fromCache) return fromCache;
  }
  const query = `match $x has internal_id_key "${escapeString(id)}"; get;`;
  const element = await load(query, ['x']);
  return element ? element.x : null;
};
export const loadEntityByStixId = async id => {
  if (!forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadByStixId(id);
    if (fromCache) return fromCache;
  }
  const query = `match $x has stix_id_key "${escapeString(id)}"; get;`;
  const element = await load(query, ['x']);
  return element ? element.x : null;
};
export const loadEntityByGraknId = async graknId => {
  if (!forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadByGraknId(graknId);
    if (fromCache) return fromCache;
  }
  const query = `match $x id ${escapeString(graknId)}; get;`;
  const element = await load(query, ['x']);
  return element.x;
};
// OBSERVABLES
export const loadObservableById = async id => {
  if (!forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadById(id, [INDEX_STIX_OBSERVABLE]);
    if (fromCache) return fromCache;
  }
  const query = `match $x has internal_id_key "${escapeString(id)}"; get;`;
  const element = await load(query, ['x']);
  return element ? element.x : null;
};
// RELATIONS
export const loadRelationById = async id => {
  if (!forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadById(id);
    if (fromCache) return fromCache;
  }
  const eid = escapeString(id);
  const query = `match $rel($from, $to) isa relation; $rel has internal_id_key "${eid}"; get;`;
  const element = await load(query, ['rel']);
  return element ? element.rel : null;
};
export const loadRelationByStixId = async id => {
  if (!forceNoCache()) {
    // [ELASTIC] From cache
    const fromCache = await elLoadByStixId(id);
    if (fromCache) return fromCache;
  }
  const eid = escapeString(id);
  const query = `match $rel($from, $to) isa relation; $rel has stix_id_key "${eid}"; get;`;
  const element = await load(query, ['rel']);
  return element ? element.rel : null;
};

/**
 * Get a single value from a Grakn query
 * @param query
 * @param infer
 * @returns {Promise<any[] | never>}
 */
export const getSingleValue = async (query, infer = false) => {
  return executeRead(async rTx => {
    logger.debug(`[GRAKN - infer: ${infer}] getSingleValue > ${query}`);
    logger.debug(`[GRAKN - infer: false] getById > ${query}`);
    const iterator = await rTx.tx.query(query, { infer });
    return iterator.next();
  });
};
export const getSingleValueNumber = async (query, infer = false) => {
  return getSingleValue(query, infer).then(data => data.number());
};

/**
 * Edit an attribute value.
 * @param id
 * @param input
 * @param wTx
 * @returns the complete instance
 */
export const updateAttribute = async (id, input, wTx) => {
  const { key, value } = input; // value can be multi valued
  // --- 00 Need update?
  const val = includes(key, multipleAttributes) ? value : head(value);
  const currentInstanceData = await loadEntityById(id);
  if (equals(currentInstanceData[key], val)) {
    return id;
  }
  // --- 01 Get the current attribute types
  const escapedKey = escape(key);
  const labelTypeQuery = `match $x type ${escapedKey}; get;`;
  const labelIterator = await wTx.tx.query(labelTypeQuery);
  const labelAnswer = await labelIterator.next();
  // eslint-disable-next-line prettier/prettier
  const attrType = await labelAnswer.map().get('x').dataType();
  const typedValues = map(v => {
    if (attrType === GraknString) return `"${escapeString(v)}"`;
    if (attrType === GraknDate) return prepareDate(v);
    return escape(v);
  }, value);
  // --- Delete the old attribute
  const entityId = `${escapeString(id)}`;
  const deleteQuery = `match $x has internal_id_key "${entityId}", has ${escapedKey} $del via $d; delete $d;`;
  // eslint-disable-next-line prettier/prettier
  logger.debug(`[GRAKN - infer: false] updateAttribute - delete > ${deleteQuery}`);
  await wTx.tx.query(deleteQuery);
  if (typedValues.length > 0) {
    let graknValues;
    if (typedValues.length === 1) {
      graknValues = `has ${escapedKey} ${head(typedValues)}`;
    } else {
      graknValues = `${join(
        ' ',
        map(gVal => `has ${escapedKey} ${gVal},`, tail(typedValues))
      )} has ${escapedKey} ${head(typedValues)}`;
    }
    const createQuery = `match $m has internal_id_key "${escapeString(id)}"; insert $m ${graknValues};`;
    logger.debug(`[GRAKN - infer: false] updateAttribute - insert > ${createQuery}`);
    await wTx.tx.query(createQuery);
  }
  // Adding dates elements
  if (includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(head(value));
    const monthValue = monthFormat(head(value));
    const yearValue = yearFormat(head(value));
    const dayInput = { key: `${key}_day`, value: [dayValue] };
    await updateAttribute(id, dayInput, wTx);
    const monthInput = { key: `${key}_month`, value: [monthValue] };
    await updateAttribute(id, monthInput, wTx);
    const yearInput = { key: `${key}_year`, value: [yearValue] };
    await updateAttribute(id, yearInput, wTx);
  }
  // Update elasticsearch
  const currentIndex = inferIndexFromConceptTypes(currentInstanceData.parent_types);
  const updateValueField = { [key]: val };
  await elUpdate(currentIndex, currentInstanceData.grakn_id, { doc: updateValueField });
  return id;
};

export const deleteEntityById = async id => {
  // 00. Load everything we need to remove in elastic
  const eid = escapeString(id);
  const read = `match $x has internal_id_key "${eid}"; $y isa entity; $rel($x, $y); get;`;
  const relationsToDeIndex = await find(read, ['rel']);
  const relationsIds = map(r => r.rel.id, relationsToDeIndex);
  return executeWrite(async wTx => {
    const query = `match $x has internal_id_key "${eid}"; $z($x, $y); delete $z, $x;`;
    logger.debug(`[GRAKN - infer: false] deleteEntityById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    await elDeleteInstanceIds(append(id, relationsIds));
    return id;
  });
};
export const deleteRelationById = async relationId => {
  const eid = escapeString(relationId);
  await executeWrite(async wTx => {
    const query = `match $x has internal_id_key "${eid}"; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteRelationById > ${query}`);
    await wTx.tx.query(query, { infer: false });
    // [ELASTIC] Update - Delete the inner indexed relations in entities
    await elRemoveRelationConnection(eid);
    await elDeleteInstanceIds([eid]);
  });
  return eid;
};

export const timeSeries = async (query, options) => {
  return executeRead(async rTx => {
    const { startDate, endDate, operation, field, interval, inferred = true } = options;
    const finalQuery = `${query}; $x has ${field}_${interval} $g; get; group $g; ${operation};`;
    logger.debug(`[GRAKN - infer: ${inferred}] timeSeries > ${finalQuery}`);
    const iterator = await rTx.tx.query(finalQuery, { infer: inferred });
    const answer = await iterator.collect();
    return Promise.all(
      answer.map(async n => {
        const date = await n.owner().value();
        const number = await n.answers()[0].number();
        return { date, value: number };
      })
    ).then(data => fillTimeSeries(startDate, endDate, interval, data));
  });
};
export const distribution = async (query, options) => {
  return executeRead(async rTx => {
    const { startDate, endDate, operation, field, inferred = false } = options;
    const finalQuery = `${query}; ${
      startDate && endDate
        ? `$rel has first_seen $fs; $fs > ${prepareDate(startDate)}; $fs < ${prepareDate(endDate)};`
        : ''
    } $x has ${field} $g; get; group $g; ${operation};`;
    logger.debug(`[GRAKN - infer: ${inferred}] distribution > ${finalQuery}`);
    const iterator = await rTx.tx.query(finalQuery, { infer: inferred });
    const answer = await iterator.collect();
    return Promise.all(
      answer.map(async n => {
        const label = await n.owner().value();
        const number = await n.answers()[0].number();
        return { label, value: number };
      })
    );
  });
};

// TODO JRI. to refactor. Change the UI.
export const findWithConnectedRelations = async (query, key, extraRelKey = null, infer = false) => {
  const dataFind = await find(query, [key, extraRelKey], { infer });
  return map(t => ({ node: t[key], relation: t[extraRelKey] }), dataFind);
};
export const loadWithConnectedRelations = (query, key, relationKey = null, infer = false) => {
  return findWithConnectedRelations(query, key, relationKey, infer).then(result => head(result));
};

// If first specified in args, the result will be paginated
export const listEntities = async (searchFields, args) => {
  // filters contains potential relations like, mitigates, tagged ...
  const { first = 200, after, withCache = true, types, search, filters, orderBy, orderMode = 'asc' } = args;
  const validFilters = filter(f => f && f.values.filter(n => n).length > 0, filters || []);
  const offset = after ? cursorToOffset(after) : 0;
  const isRelationOrderBy = orderBy && includes('.', orderBy);
  // 01. Define if Elastic can support this query.
  let supportedByCache = true;
  // 01-2 Check the filters
  const relationFilters = filter(k => {
    // If the relation must be forced in a specific direction, ES cant support it.
    if (k.entityRole) return false;
    const isRelationFilter = includes('.', k.key);
    if (isRelationFilter) {
      // ES only support internal_id reference
      const [, field] = k.key.split('.');
      if (field !== 'internal_id_key') return false;
    }
    return isRelationFilter;
  }, validFilters);
  supportedByCache = supportedByCache && relationFilters.length === 0;
  // 02. If not go with standard Grakn
  const relationsFields = [];
  const attributesFields = [];
  const attributesFilters = [];
  // Handle order by field
  if (isRelationOrderBy) {
    const [relation, field] = orderBy.split('.');
    if (field !== 'internal_id_key') supportedByCache = false;
    relationsFields.push(`($elem, $${relation}) isa ${relation}; $${relation} has ${field} $order;`);
  } else if (orderBy) {
    attributesFields.push(`$elem has ${orderBy} $order;`);
  }
  // Handle filters
  const relationFiltersIds = [];
  if (validFilters && validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const filterKey = validFilters[index].key;
      const filterValues = validFilters[index].values;
      const isRelationFilter = includes('.', filterKey);
      if (isRelationFilter) {
        const [relation, field] = filterKey.split('.');
        const sourceRole = validFilters[index].sourceRole ? `${validFilters[index].sourceRole}:` : '';
        const targetRef = relation;
        const relId = `rel_${relation}`;
        relationsFields.push(`$${relId} (${sourceRole}$elem, $${targetRef}) isa ${relation};`);
        for (let valueIndex = 0; valueIndex < filterValues.length; valueIndex += 1) {
          const val = filterValues[valueIndex];
          // Apply filter on target.
          // TODO Support more than only String filters
          attributesFields.push(`$${targetRef} has ${field} "${val}";`);
          relationFiltersIds.push({ relation, field, val });
        }
      } else {
        for (let valueIndex = 0; valueIndex < filterValues.length; valueIndex += 1) {
          const val = filterValues[valueIndex];
          attributesFields.push(`$elem has ${filterKey} "${escapeString(val)}";`);
        }
      }
    }
  }
  // Handle special case of search
  if (search) {
    for (let searchIndex = 0; searchIndex < searchFields.length; searchIndex += 1) {
      const searchFieldName = searchFields[searchIndex];
      attributesFields.push(`$elem has ${searchFieldName} $${searchFieldName};`);
    }
    const searchFilter = pipe(
      map(e => `{ $${e} contains "${escapeString(search)}"; }`),
      join(' or ')
    )(searchFields);
    attributesFilters.push(`${searchFilter};`);
  }
  // build the final query
  const queryAttributesFields = join(' ', attributesFields);
  const queryAttributesFilters = join(' ', attributesFilters);
  const queryRelationsFields = join(' ', relationsFields);
  const headType = types.length === 1 ? head(types) : 'entity';
  const extraTypes =
    types.length > 1
      ? pipe(
          map(e => `{ $elem isa ${e}; }`),
          join(' or '),
          concat(__, ';')
        )(types)
      : '';
  const baseQuery = `match $elem isa ${headType}; ${extraTypes} ${queryRelationsFields} 
                      ${queryAttributesFields} ${queryAttributesFilters} get;`;
  const countQuery = `${baseQuery} count;`;
  const paginateQuery = `offset ${offset}; limit ${first};`;
  const orderQuery = orderBy ? `sort $order ${orderMode};` : '';
  const query = `${baseQuery} ${orderQuery} ${paginateQuery}`;
  // In case of only one relation filters, we can specify the relation extra key
  if (relationFiltersIds.length > 1) {
    logger.warn('[GRAKN] List entities through multiple relations, selecting first one...');
  }
  const relationToGet = head(relationFiltersIds);
  // [ELASTIC] From cache
  const getInGrakn = forceNoCache();
  if (supportedByCache && withCache && !getInGrakn) {
    const index = inferIndexFromConceptTypes(args.types);
    const paginateResult = await elPaginate(index, args);
    if (relationToGet) {
      // A relation is require, reconstruct the result with it.
      return {
        pageInfo: paginateResult.pageInfo,
        edges: map(e => {
          const rel = RamdaFind(i => i.internal_id_key === relationToGet.val, e.node[relationToGet.relation]);
          return {
            node: e.node,
            relation: { id: rel.relation_id_key },
            cursor: e.cursor
          };
        }, paginateResult.edges)
      };
    }
    return paginateResult;
  }
  // TODO JRI Remove this
  logger.debug(`[GRAKN] ListEntities on Grakn, supportedByCache: ${supportedByCache} 
    / withCache: ${withCache} 
    / forceNoCache: ${getInGrakn}`);
  // noinspection ES6MissingAwait
  const countPromise = getSingleValueNumber(countQuery);
  const extraRelation = relationToGet ? relationToGet.id : undefined;
  const instancesPromise = await findWithConnectedRelations(query, 'elem', extraRelation);
  return Promise.all([instancesPromise, countPromise]).then(([instances, globalCount]) => {
    return buildPagination(first, offset, instances, globalCount);
  });
};

// TODO JRI Finish this
/*
export const listRelations = async args => {
  const { first = 200, after, filters, orderBy, orderMode = 'asc' } = args;
  const { types, fromRole, fromId, toRole, toId, fromTypes, toTypes } = args;
  // const { firstSeenStart, firstSeenStop, lastSeenStart, lastSeenStop, weights } = args;
  const offset = after ? cursorToOffset(after) : 0;
  // Handle relation type(s)
  const relationType = types.length === 1 ? head(types) : 'stix_relation';
  const queryTypes =
    types.length > 1
      ? pipe(
          map(e => `{ $elem isa ${e}; }`),
          join(' or '),
          concat(__, ';')
        )(types)
      : '';
  // eslint-disable-next-line prettier/prettier
  const queryFromTypes = pipe(map(e => `{ $from isa ${e}; }`), join(' or '), concat(__, ';'))(fromTypes);
  // eslint-disable-next-line prettier/prettier
  const queryToTypes = pipe(map(e => `{ $to isa ${e}; }`), join(' or '), concat(__, ';'))(fromTypes);
  // Build the query
  const relFrom = fromRole ? `${fromRole}:` : '';
  const relTo = toRole ? `${toRole}:` : '';
  const baseQuery = `match $rel(${relFrom}$from, ${relTo}$to) isa ${relationType};
                      ${queryTypes} ${queryFromTypes} ${queryToTypes}
                      ${queryAttributesFields} ${queryAttributesFilters} get;`;
};
*/
// endregion

// region please refactor to use stable commands
/**
 * Load any grakn relation with base64 id containing the query pattern.
 * @param id
 * @returns {Promise}
 */
export const getRelationInferredById = async id => {
  return executeRead(async rTx => {
    const decodedQuery = Buffer.from(id, 'base64').toString('ascii');
    const query = `match ${decodedQuery} get;`;
    const queryRegex = /\$([a-z_\d]+)\s?[([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\s[a-z_]+\s([\w-]+);/i.exec(query);
    if (queryRegex === null) return {};
    const relKey = queryRegex[1];
    logger.debug(`[GRAKN - infer: true] getRelationInferredById > ${query}`);
    const answerIterator = await rTx.tx.query(query);
    const answer = await answerIterator.next();
    const rel = answer.map().get(relKey);
    const relationType = await rel.type();
    const relationTypeValue = await relationType.label();
    const rolePlayersMap = await rel.rolePlayersMap();
    const roles = rolePlayersMap.keys();
    const fromRole = roles.next().value;
    // eslint-disable-next-line prettier/prettier
    const fromObject = rolePlayersMap.get(fromRole).values().next().value;
    const fromRoleLabel = await fromRole.label();
    const toRole = roles.next().value;
    // eslint-disable-next-line prettier/prettier
    const toObject = rolePlayersMap.get(toRole).values().next().value;
    const toRoleLabel = await toRole.label();
    const relation = {
      id,
      entity_type: TYPE_STIX_RELATION,
      relationship_type: relationTypeValue,
      inferred: true
    };
    const fromPromise = loadConcept(fromObject);
    const toPromise = loadConcept(toObject);
    const explanation = answer.explanation();
    const explanationAnswers = explanation.answers();
    const inferences = explanationAnswers.map(explanationAnswer => {
      const explanationAnswerExplanation = explanationAnswer.explanation();
      let inferenceQuery = explanationAnswerExplanation.queryPattern();
      const inferenceQueryRegex = /(\$(\d+|rel)\s)?\([a-z_]+:\s\$(\w+),\s[a-z_]+:\s\$(\w+)\)\sisa\s([\w-]+);/i.exec(
        inferenceQuery
      );
      let relationKey;
      const [, , inferReferenceRelationKey] = inferenceQueryRegex;
      if (inferReferenceRelationKey !== undefined) {
        relationKey = inferReferenceRelationKey;
      } else {
        relationKey = randomKey(5);
        inferenceQuery = inferenceQuery.replace('(', `$${relationKey} (`);
      }
      return {
        inferenceQuery,
        relationKey,
        fromKey: inferenceQueryRegex[3],
        toKey: inferenceQueryRegex[4],
        relationType: inferenceQueryRegex[5]
      };
    });
    const inferencesQueries = pluck('inferenceQuery', inferences);
    const inferencesQuery = `match {${join(' ', inferencesQueries)} }; get;`;
    logger.debug(`[GRAKN - infer: true] getRelationInferredById - getInferences > ${inferencesQuery}`);
    const inferencesAnswerIterator = await rTx.tx.query(inferencesQuery);
    const inferencesAnswer = await inferencesAnswerIterator.next();
    const inferencesPromises = Promise.all(
      inferences.map(async inference => {
        const inferred = await inferencesAnswer
          .map()
          .get(inference.relationKey)
          .isInferred();
        const inferenceFrom = inferencesAnswer.map().get(inference.fromKey);
        const inferenceTo = inferencesAnswer.map().get(inference.toKey);
        let inferenceId;
        if (inferred) {
          const inferenceQueryRegex = /\$([a-z_\d]+)\s\([a-z_:]+\s\$([a-z_]+),\s[a-z_:]+\s\$([a-z_]+)\)/i.exec(
            inference.inferenceQuery
          );
          const entityFromKey = inferenceQueryRegex[2];
          const entityToKey = inferenceQueryRegex[3];
          const regexFromString = `\\$${entityFromKey}\\sid\\s(V\\d+);`;
          const regexFrom = new RegExp(regexFromString, 'i');
          const inferenceQueryRegexFrom = inference.inferenceQuery.match(regexFrom);
          const regexToString = `\\$${entityToKey}\\sid\\s(V\\d+);`;
          const regexTo = new RegExp(regexToString, 'i');
          const inferenceQueryRegexTo = inference.inferenceQuery.match(regexTo);

          const regexFromTypeString = `\\$${entityFromKey}\\sisa\\s[\\w-_]+;`;
          const regexFromType = new RegExp(regexFromTypeString, 'ig');
          const regexToTypeString = `\\$${entityToKey}\\sisa\\s[\\w-_]+;`;
          const regexToType = new RegExp(regexToTypeString, 'ig');

          let extractedInferenceQuery;
          if (inferenceQueryRegexFrom && inferenceQueryRegexTo) {
            extractedInferenceQuery = inference.inferenceQuery;
          } else if (inferenceQueryRegexFrom) {
            const existingId = inferenceQueryRegexFrom[1];
            extractedInferenceQuery = inference.inferenceQuery.replace(
              `$${entityFromKey} id ${existingId};`,
              `$${entityFromKey} id ${existingId}; $${entityToKey} id ${
                existingId === inferenceFrom.id ? inferenceTo.id : inferenceFrom.id
              };`
            );
          } else if (inferenceQueryRegexTo) {
            const existingId = inferenceQueryRegexTo[1];
            extractedInferenceQuery = inference.inferenceQuery.replace(
              `$${entityToKey} id ${existingId};`,
              `$${entityToKey} id ${existingId}; $${entityFromKey} id ${
                existingId === inferenceFrom.id ? inferenceTo.id : inferenceFrom.id
              };`
            );
          } else {
            extractedInferenceQuery = inference.inferenceQuery;
          }
          const finalInferenceQuery = extractedInferenceQuery.replace(regexFromType, '').replace(regexToType, '');
          inferenceId = Buffer.from(finalInferenceQuery).toString('base64');
        } else {
          const inferenceAttributes = await loadConcept(inferencesAnswer.map().get(inference.relationKey));
          inferenceId = inferenceAttributes.internal_id_key;
        }
        const fromAttributes = await loadConcept(inferenceFrom);
        const toAttributes = await loadConcept(inferenceTo);
        return {
          node: {
            id: inferenceId,
            inferred,
            relationship_type: inference.relationType,
            from: fromAttributes,
            to: toAttributes
          }
        };
      })
    );
    return Promise.all([fromPromise, toPromise, inferencesPromises]).then(
      ([fromResult, toResult, relationInferences]) => {
        if (isInversed(relation.relationship_type, fromRoleLabel)) {
          return pipe(
            assoc('from', toResult),
            assoc('fromRole', toRoleLabel),
            assoc('to', fromResult),
            assoc('toRole', fromRoleLabel),
            assoc('inferences', { edges: relationInferences })
          )(relation);
        }
        return pipe(
          assoc('from', fromResult),
          assoc('fromRole', fromRoleLabel),
          assoc('to', toResult),
          assoc('toRole', toRoleLabel),
          assoc('inferences', { edges: relationInferences })
        )(relation);
      }
    );
  });
};

// TODO JRI REFACTOR paginateRelationships
/**
 * Grakn generic pagination query
 * @param query
 * @param options
 * @param key
 * @param extraRel
 * @param pagination
 * @returns Promise
 */
export const paginateRelationships = async (query, options, key = 'rel', extraRel = null, pagination = true) => {
  try {
    const {
      first = 200,
      after,
      types = ['stix_relation'],
      inferred,
      fromId,
      fromTypes = [],
      toId,
      toTypes = [],
      orderBy,
      orderMode = 'asc',
      firstSeenStart,
      firstSeenStop,
      lastSeenStart,
      lastSeenStop,
      weights,
      canUseCache = false
    } = options;
    // Only use Elastic if no extra relation needed and inferred of course.
    if (
      canUseCache && // Explicitly express that can use the cache
      (inferred === undefined || inferred === false) && // Only for real relations
      extraRel === null && // No support of relation to relation
      fromTypes.length <= 1 && // Can only force one type with current elPaginate
      toTypes.length <= 1 // Can only force one type with current elPaginate
    ) {
      const filters = [];
      if (fromTypes.length > 0) filters.push({ key: 'fromTypes', values: fromTypes });
      if (toTypes.length > 0) filters.push({ key: 'toTypes', values: toTypes });
      if (fromId) {
        const from = await loadEntityById(fromId);
        filters.push({ key: 'fromId', values: [from.grakn_id] });
      }
      if (toId) {
        const to = await loadEntityById(toId);
        filters.push({ key: 'toId', values: [to.grakn_id] });
      }
      if (firstSeenStart) filters.push({ key: 'first_seen', operator: 'gt', values: [firstSeenStart] });
      if (firstSeenStop) filters.push({ key: 'first_seen', operator: 'lt', values: [firstSeenStop] });
      if (lastSeenStart) filters.push({ key: 'last_seen', operator: 'gt', values: [lastSeenStart] });
      if (lastSeenStop) filters.push({ key: 'last_seen', operator: 'lt', values: [lastSeenStop] });
      if (weights) filters.push({ key: 'weight', values: weights });
      return elPaginate(INDEX_STIX_RELATIONS, {
        first,
        after,
        types,
        orderBy,
        orderMode,
        filters
      });
    }
    console.log(
      `[GRAKN] FETCH grakn relations (inferred: ${inferred} / extraRel: ${extraRel} / fromTypes: ${fromTypes.length} / toTypes: ${toTypes.length})`
    );
    const offset = after ? cursorToOffset(after) : 0;
    const finalQuery = `
      ${query};
      ${fromId ? `$from has internal_id_key "${escapeString(fromId)}";` : ''}
      ${toId ? `$to has internal_id_key "${escapeString(toId)}";` : ''} 
      ${
        fromTypes.length > 0
          ? `${join(' ', map(fromType => `{ $from isa ${fromType}; } or`, tail(fromTypes)))} { $from isa ${head(
              fromTypes
            )}; };`
          : ''
      } 
    ${
      toTypes.length > 0
        ? `${join(' ', map(toType => `{ $to isa ${toType}; } or`, tail(toTypes)))} { $to isa ${head(toTypes)}; };`
        : ''
    } 
      ${firstSeenStart || firstSeenStop ? `$rel has first_seen $fs; ` : ''} 
      ${firstSeenStart ? `$fs > ${prepareDate(firstSeenStart)}; ` : ''} 
      ${firstSeenStop ? `$fs < ${prepareDate(firstSeenStop)}; ` : ''} 
      ${lastSeenStart || lastSeenStop ? `$rel has last_seen $ls; ` : ''} 
      ${lastSeenStart ? `$ls > ${prepareDate(lastSeenStart)}; ` : ''} 
      ${lastSeenStop ? `$ls < ${prepareDate(lastSeenStop)}; ` : ''} 
      ${
        weights
          ? `$rel has weight $weight; ${join(
              ' ',
              map(weight => `{ $weight == ${weight}; } or`, tail(weights))
            )} { $weight == ${head(weights)}; };`
          : ''
      }`;
    const orderingKey = orderBy ? `$rel has ${orderBy} $o;` : '';
    const count = getSingleValueNumber(`${finalQuery} ${orderingKey} get; count;`, inferred);
    const elements = findWithConnectedRelations(
      `${finalQuery} ${orderingKey} get; ${orderBy ? `sort $o ${orderMode};` : ''} offset ${offset}; limit ${first};`,
      key,
      extraRel,
      inferred
    );
    if (pagination) {
      return Promise.all([count, elements]).then(data => {
        const globalCount = data ? head(data) : 0;
        const instances = data ? last(data) : [];
        return buildPagination(first, offset, instances, globalCount);
      });
    }
    return Promise.all([count, elements]).then(data => {
      const globalCount = data ? head(data) : 0;
      const instances = data ? last(data) : [];
      return { globalCount, instances };
    });
  } catch (err) {
    logger.error('[GRAKN] paginateRelationships error > ', err);
    return null;
  }
};
// endregion

const prepareAttribute = value => {
  if (value instanceof Date) return prepareDate(value);
  if (Date.parse(value) > 0 && new Date(value).toISOString() === value) return prepareDate(value);
  if (typeof value === 'string') return `"${escapeString(value)}"`;
  return escape(value);
};
const flatAttributesForObject = data => {
  const elements = Object.entries(data);
  return pipe(
    map(elem => {
      const key = head(elem);
      const value = last(elem);
      if (Array.isArray(value)) {
        return map(iter => ({ key, value: iter }), value);
      }
      // Some dates needs to detailed for search
      if (value && includes(key, statsDateAttributes)) {
        return [
          { key, value },
          { key: `${key}_day`, value: dayFormat(value) },
          { key: `${key}_month`, value: monthFormat(value) },
          { key: `${key}_year`, value: yearFormat(value) }
        ];
      }
      return { key, value };
    }),
    flatten,
    filter(f => f.value !== undefined)
  )(elements);
};
const createRelationRaw = async (fromInternalId, input, opts = {}) => {
  const { indexable = true } = opts;
  const relationId = uuid();
  // 01. First fix the direction of the relation
  const isStixRelation = includes('stix_id_key', Object.keys(input)) || input.relationship_type;
  const relationshipType = input.relationship_type || input.through;
  const entityType = isStixRelation ? TYPE_STIX_RELATION : TYPE_RELATION_EMBEDDED;
  const isInv = isInversed(relationshipType, input.fromRole);
  if (isInv) logger.warn('[GRAKN] You try to create a relation in incorrect order, reversing...', input);
  const data = pipe(
    assoc('fromId', isInv ? input.toId : fromInternalId),
    assoc('fromRole', isInv ? input.toRole : input.fromRole),
    assoc('toId', isInv ? fromInternalId : input.toId),
    assoc('toRole', isInv ? input.fromRole : input.toRole)
  )(input);
  // 02. Prepare the data to create or index
  const relationAttributes = { internal_id_key: relationId };
  if (isStixRelation) {
    const currentDate = now();
    const toCreate = data.stix_id_key === undefined || data.stix_id_key === 'create';
    relationAttributes.stix_id_key = toCreate ? `relationship--${uuid()}` : data.stix_id_key;
    relationAttributes.revoked = false;
    relationAttributes.name = data.name ? data.name : ''; // Force name of the relation
    relationAttributes.description = data.description;
    relationAttributes.role_played = data.role_played ? data.role_played : 'Unknown';
    relationAttributes.score = data.score ? data.score : 50;
    relationAttributes.weight = data.weight;
    relationAttributes.expiration = data.expiration;
    relationAttributes.entity_type = entityType;
    relationAttributes.relationship_type = relationshipType;
    relationAttributes.updated_at = currentDate;
    relationAttributes.created = input.created;
    relationAttributes.modified = input.modified;
    relationAttributes.created_at = currentDate;
    relationAttributes.first_seen = input.first_seen;
    relationAttributes.last_seen = input.last_seen;
    relationAttributes.expiration = input.expiration;
  }
  // 02. Create the relation
  const graknRelation = await executeWrite(async wTx => {
    let query = `match $from has internal_id_key "${data.fromId}";
      $to has internal_id_key "${data.toId}";
      insert $rel(${data.fromRole}: $from, ${data.toRole}: $to) isa ${relationshipType},`;
    const queryElements = flatAttributesForObject(relationAttributes);
    const nbElements = queryElements.length;
    for (let index = 0; index < nbElements; index += 1) {
      const { key, value } = queryElements[index];
      const insert = prepareAttribute(value);
      const separator = index + 1 === nbElements ? ';' : ',';
      query += `has ${key} ${insert}${separator} `;
    }
    logger.debug(`[GRAKN - infer: false] createRelation > ${query}`);
    const iterator = await wTx.tx.query(query);
    const txRelation = await iterator.next();
    const conceptRelation = txRelation.map().get('rel');
    const relationTypes = await conceptTypes(conceptRelation);
    const graknRelationId = conceptRelation.id;
    const conceptFrom = txRelation.map().get('from');
    const graknFromId = conceptFrom.id;
    const fromTypes = await conceptTypes(conceptFrom);
    const conceptTo = txRelation.map().get('to');
    const graknToId = conceptTo.id;
    const toTypes = await conceptTypes(conceptTo);
    return { graknRelationId, graknFromId, graknToId, relationTypes, fromTypes, toTypes };
  });
  // 03. Prepare the final data with grakn IDS
  const createdRel = pipe(
    assoc('id', relationId),
    // Grakn identifiers
    assoc('grakn_id', graknRelation.graknRelationId),
    assoc('fromId', graknRelation.graknFromId),
    assoc('fromTypes', graknRelation.fromTypes),
    assoc('toId', graknRelation.graknToId),
    assoc('toTypes', graknRelation.toTypes),
    // Relation specific
    assoc('inferred', false),
    // Types
    assoc('entity_type', entityType),
    assoc('relationship_type', relationshipType),
    assoc('parent_types', graknRelation.relationTypes)
  )(relationAttributes);
  if (indexable) {
    // 04. Index the relation and the modification in the base entity
    await indexElements([createdRel]);
  }
  // 06. Return result
  return createdRel;
};

// region business relations
const addOwner = async (fromInternalId, createdByOwnerId, opts = {}) => {
  if (!createdByOwnerId) return undefined;
  const input = { fromRole: 'to', toId: createdByOwnerId, toRole: 'owner', through: 'owned_by' };
  return createRelationRaw(fromInternalId, input, opts);
};
const addCreatedByRef = async (fromInternalId, createdByRefId, opts = {}) => {
  if (!createdByRefId) return undefined;
  const input = { fromRole: 'so', toId: createdByRefId, toRole: 'creator', through: 'created_by_ref' };
  return createRelationRaw(fromInternalId, input, opts);
};
const addMarkingDef = async (fromInternalId, markingDefId, opts = {}) => {
  if (!markingDefId) return undefined;
  const input = { fromRole: 'so', toId: markingDefId, toRole: 'marking', through: 'object_marking_refs' };
  return createRelationRaw(fromInternalId, input, opts);
};
const addMarkingDefs = async (internalId, markingDefIds, opts = {}) => {
  if (!markingDefIds || isEmpty(markingDefIds)) return undefined;
  const markings = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < markingDefIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const marking = await addMarkingDef(internalId, markingDefIds[i], opts);
    markings.push(marking);
  }
  return markings;
};
const addKillChain = async (fromInternalId, killChainId, opts = {}) => {
  if (!killChainId) return undefined;
  const input = {
    fromRole: 'phase_belonging',
    toId: killChainId,
    toRole: 'kill_chain_phase',
    through: 'kill_chain_phases'
  };
  return createRelationRaw(fromInternalId, input, opts);
};
const addKillChains = async (internalId, killChainIds, opts = {}) => {
  if (!killChainIds || isEmpty(killChainIds)) return undefined;
  const killChains = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < killChainIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const killChain = await addKillChain(internalId, killChainIds[i], opts);
    killChains.push(killChain);
  }
  return killChains;
};
// endregion

export const createRelation = async (fromInternalId, input, opts = {}) => {
  const created = await createRelationRaw(fromInternalId, input, opts);
  // 05. Complete with eventual relations (will eventually update the index)
  await addOwner(created.id, input.createdByOwner, opts);
  await addCreatedByRef(created.id, input.createdByRef, opts);
  await addMarkingDefs(created.id, input.markingDefinitions, opts);
  await addKillChains(created.id, input.killChainPhases, opts);
  return created;
};
export const createRelations = async (fromInternalId, inputs, opts = {}) => {
  const createdRelations = [];
  // Relations cannot be created in parallel. (Concurrent indexing on same key)
  // Could be improve by grouping and indexing in one shot.
  for (let i = 0; i < inputs.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const relation = await createRelation(fromInternalId, inputs[i], opts);
    createdRelations.push(relation);
  }
  return createdRelations;
};
export const createEntity = async (entity, type, opts = {}) => {
  const { modelType = TYPE_STIX_DOMAIN_ENTITY, stixIdType, indexable = true } = opts;
  const internalId = entity.internal_id_key ? entity.internal_id_key : uuid();
  const stixType = stixIdType || type.toLowerCase();
  const stixId = entity.stix_id_key ? entity.stix_id_key : `${stixType}--${uuid()}`;
  // Complete with identifiers
  const today = now();
  let data = pipe(
    assoc('internal_id_key', internalId),
    assoc('entity_type', type.toLowerCase()),
    assoc('created_at', today),
    assoc('updated_at', today),
    dissoc('createdByOwner'),
    dissoc('createdByRef'),
    dissoc('markingDefinitions'),
    dissoc('killChainPhases'),
    dissoc('password')
  )(entity);
  // For stix domain entity, force the initialization of the alias list.
  if (modelType === TYPE_STIX_DOMAIN_ENTITY) {
    data = pipe(assoc('alias', data.alias ? data.alias : ['']))(data);
  }
  if (modelType === TYPE_STIX_OBSERVABLE) {
    data = pipe(
      assoc('stix_id_key', stixId),
      assoc('name', data.name ? data.name : '')
    )(data);
  }
  if (modelType === TYPE_STIX_DOMAIN || modelType === TYPE_STIX_DOMAIN_ENTITY) {
    data = pipe(
      assoc('stix_id_key', stixId),
      assoc('created', entity.created ? entity.created : today),
      assoc('modified', entity.modified ? entity.modified : today),
      assoc('revoked', false)
    )(data);
  }
  // Generate fields for query and build the query
  const queryElements = flatAttributesForObject(data);
  const nbElements = queryElements.length;
  let query = `insert $entity isa ${type}, `;
  for (let index = 0; index < nbElements; index += 1) {
    const { key, value } = queryElements[index];
    const insert = prepareAttribute(value);
    const separator = index + 1 === nbElements ? ';' : ',';
    query += `has ${key} ${insert}${separator} `;
  }
  const entityCreated = await executeWrite(async wTx => {
    const iterator = await wTx.tx.query(query);
    const txEntity = await iterator.next();
    const concept = txEntity.map().get('entity');
    const types = await conceptTypes(concept);
    return { id: concept.id, types };
  });
  // Transaction succeed, complete the result to send it back
  const completedData = pipe(
    assoc('id', internalId),
    // Grakn identifiers
    assoc('grakn_id', entityCreated.id),
    // Types (entity type directly saved)
    assoc('parent_types', entityCreated.types)
  )(data);
  // Transaction succeed, index the result
  if (indexable) {
    await indexElements([completedData]);
  }
  // Complete with eventual relations (will eventually update the index)
  await addOwner(internalId.id, entity.createdByOwner, opts);
  await addCreatedByRef(internalId, entity.createdByRef, opts);
  await addMarkingDefs(internalId, entity.markingDefinitions, opts);
  await addKillChains(internalId, entity.killChainPhases, opts);
  // Else simply return the data
  return completedData;
};
