import {
  __,
  ascend,
  assoc,
  chain,
  compose,
  concat,
  descend,
  dissoc,
  equals,
  filter,
  find as Rfind,
  flatten,
  forEach,
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
  prop,
  sortBy,
  sortWith,
  split,
  tail,
  take,
  toLower,
  toPairs,
  type as Rtype,
  uniq,
  uniqBy,
} from 'ramda';
import moment from 'moment';
import { cursorToOffset } from 'graphql-relay/lib/connection/arrayconnection';
import Grakn from 'grakn-client';
import {
  DatabaseError,
  DuplicateEntryError,
  FunctionalError,
  MissingReferenceError,
  TYPE_DUPLICATE_ENTRY,
} from '../config/errors';
import conf, { logger } from '../config/conf';
import { buildPagination, fillTimeSeries, inferIndexFromConceptType, utcDate } from './utils';
import {
  elAggregationCount,
  elAggregationRelationsCount,
  elBulk,
  elDeleteInstanceIds,
  elHistogramCount,
  elIndexElements,
  elLoadById,
  elLoadByStixId,
  elPaginate,
  elRemoveRelationConnection,
  elUpdate,
  useCache,
  REL_INDEX_PREFIX,
  ENTITIES_INDICES,
  RELATIONSHIPS_INDICES,
} from './elasticSearch';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_UPDATE,
  EVENT_TYPE_UPDATE_ADD,
  EVENT_TYPE_UPDATE_REMOVE,
  sendLog,
} from './rabbitmq';
import {
  BASE_TYPE_ENTITY,
  BASE_TYPE_RELATION,
  generateStandardId,
  isStixMetaRelationship,
  isInternalObject,
  isStixCoreObject,
  isStixDomainObject,
  isStixId,
  isStixCoreRelationship,
  RELATION_OBJECT_LABEL,
  RELATION_CREATED_BY,
  RELATION_OBJECT_MARKING,
  RELATION_OBJECT,
  RELATION_KILL_CHAIN_PHASE,
  isStixObject,
  isStixMetaObject,
  isStixSightingRelationship,
  isStixRelationship,
  generateInternalId,
  ABSTRACT_BASIC_RELATIONSHIP,
  isStixCyberObservableRelationship,
  getParentTypes,
  isBasicObject,
  isBasicRelationship,
  ABSTRACT_STIX_RELATIONSHIP,
  isAbstract,
  isDatedInternalObject,
  RELATION_EXTERNAL_REFERENCE,
} from '../utils/idGenerator';
import { lockResource } from './redis';
import { STIX_SPEC_VERSION } from './stix';

// region global variables
export const FROM_START = 0; // "1970-01-01T00:00:00.000Z"
export const UNTIL_END = 100000000000000; // "5138-11-16T09:46:40.000Z"
const dateFormat = 'YYYY-MM-DDTHH:mm:ss.SSS';
const GraknString = 'String';
const GraknDate = 'Date';

export const REL_CONNECTED_SUFFIX = 'CONNECTED';
export const TYPE_STIX_DOMAIN = 'Stix-Domain';
const INFERRED_RELATION_KEY = 'rel';

export const now = () => utcDate().toISOString();
export const sinceNowInMinutes = (lastModified) => {
  const diff = utcDate().diff(utcDate(lastModified));
  const duration = moment.duration(diff);
  return Math.floor(duration.asMinutes());
};
export const prepareDate = (date) => utcDate(date).format(dateFormat);
export const yearFormat = (date) => utcDate(date).format('YYYY');
export const monthFormat = (date) => utcDate(date).format('YYYY-MM');
export const dayFormat = (date) => utcDate(date).format('YYYY-MM-DD');

export const escape = (chars) => {
  const toEscape = chars && typeof chars === 'string';
  if (toEscape) {
    return chars.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,');
  }
  return chars;
};
export const escapeString = (s) => (s ? s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') : '');

// Attributes key that can contains multiple values.
export const multipleAttributes = [
  'stix_ids',
  'aliases',
  'grant',
  'indicator_types',
  'infrastructure_types',
  'secondary_motivations',
  'malware_types',
  'architecture_execution_envs',
  'implementation_languages',
  'capabilities',
  'authors',
  'report_types',
  'threat_actor_types',
  'personal_motivations',
  'goals',
  'roles',
  'tool_types',
  'received_lines',
  'environment_variables',
  'languages',
  'x_mitre_platforms',
  'x_mitre_permissions_required',
  'x_opencti_aliases',
];
export const statsDateAttributes = [
  'created_at',
  'first_seen',
  'last_seen',
  'start_time',
  'stop_time',
  'published',
  'valid_from',
  'valid_until',
];
// endregion

// region client
const client = new Grakn(`${conf.get('grakn:hostname')}:${conf.get('grakn:port')}`);
let session = null;
// endregion

// region basic commands
const closeTx = async (gTx) => {
  if (gTx.isOpen()) {
    return gTx.close().catch(
      /* istanbul ignore next */ (err) => {
        throw DatabaseError('[GRAKN] CloseReadTx error', { grakn: err.details });
      }
    );
  }
  return true;
};

const takeReadTx = async () => {
  if (session === null) session = await client.session('grakn');
  return session
    .transaction()
    .read()
    .catch(
      /* istanbul ignore next */ (err) => {
        if (err.code === 2 && session) {
          session = null;
          return takeReadTx();
        }
        throw DatabaseError('[GRAKN] TakeReadTx error', { grakn: err.details });
      }
    );
};
export const executeRead = async (executeFunction) => {
  const rTx = await takeReadTx();
  try {
    const result = await executeFunction(rTx);
    await closeTx(rTx);
    return result;
  } catch (err) {
    await closeTx(rTx);
    /* istanbul ignore next */
    throw err;
  }
};

const takeWriteTx = async () => {
  if (session === null) session = await client.session('grakn');
  return session
    .transaction()
    .write()
    .catch(
      /* istanbul ignore next */ (err) => {
        if (err.code === 2 && session) {
          session = null;
          return takeWriteTx();
        }
        throw DatabaseError('[GRAKN] TakeWriteTx error', { grakn: err.details });
      }
    );
};
const commitWriteTx = async (wTx) => {
  return wTx.commit().catch(
    /* istanbul ignore next */ (err) => {
      if (err.code === 3) {
        const errorDetail = split('\n', err.details)[1];
        // In grakn, its not possible yet to have structured errors.
        // We need to extract the information from the message.
        // There is more than one thing of type [XX] that owns the key [XX] of type [XX].
        const messageRegExp = /.*more than one thing.*owns the key \[([a-z0-9\\-]+)\] of type \[([a-z_]+)\]/;
        const duplicateMatcher = errorDetail.match(messageRegExp);
        if (duplicateMatcher) {
          const message = 'Element already exists (grakn)';
          throw DuplicateEntryError(message, { id: duplicateMatcher[1], field: duplicateMatcher[2] });
        }
      }
      throw DatabaseError('[GRAKN] CommitWriteTx error', { grakn: err.details });
    }
  );
};

export const executeWrite = async (executeFunction) => {
  const wTx = await takeWriteTx();
  try {
    const result = await executeFunction(wTx);
    await commitWriteTx(wTx);
    return result;
  } catch (err) {
    await closeTx(wTx);
    /* istanbul ignore next */
    throw err;
  }
};
export const internalDirectWrite = async (query) => {
  const wTx = await takeWriteTx();
  return wTx
    .query(query)
    .then(() => commitWriteTx(wTx))
    .catch(
      /* istanbul ignore next */ async (err) => {
        await closeTx(wTx);
        logger.error('[GRAKN] Write error', { error: err });
        throw err;
      }
    );
};

export const graknIsAlive = async () => {
  return executeRead(() => {})
    .then(() => true)
    .catch(
      /* istanbul ignore next */ () => {
        throw DatabaseError('Grakn seems down');
      }
    );
};
export const getGraknVersion = () => {
  // It seems that Grakn server does not expose its version yet:
  // https://github.com/graknlabs/client-nodejs/issues/47
  return '1.7.2';
};

const getAliasInternalIdFilter = (query, alias) => {
  const reg = new RegExp(`\\$${alias}[\\s]*has[\\s]*internal_id[\\s]*"([0-9a-z-_]+)"`, 'gi');
  const keyVars = Array.from(query.matchAll(reg));
  return keyVars.length > 0 ? last(head(keyVars)) : undefined;
};
/**
 * Extract all vars from a grakn query
 * @param query
 */
export const extractQueryVars = (query) => {
  const vars = uniq(map((m) => ({ alias: m.replace('$', '') }), query.match(/\$[a-z_]+/gi)));
  const varWithKey = map((v) => ({ alias: v.alias, internalIdKey: getAliasInternalIdFilter(query, v.alias) }), vars);
  const relationsVars = Array.from(query.matchAll(/\(([a-z_\-\s:$]+),([a-z_\-\s:$]+)\)[\s]*isa[\s]*([a-z_-]+)/g));
  const roles = flatten(
    map((r) => {
      const [, left, right, relationshipType] = r;
      const [leftRole, leftAlias] = includes(':', left) ? left.trim().split(':') : [null, left];
      const [rightRole, rightAlias] = includes(':', right) ? right.trim().split(':') : [null, right];
      const roleForLeft =
        leftRole || (rightRole && rightRole.includes('_from') ? `${relationshipType}_to` : `${relationshipType}_from`);
      const roleForRight =
        rightRole || (leftRole && leftRole.includes('_to') ? `${relationshipType}_from` : `${relationshipType}_to`);
      const lAlias = leftAlias.trim().replace('$', '');
      const lKeyFilter = getAliasInternalIdFilter(query, lAlias);
      const rAlias = rightAlias.trim().replace('$', '');
      const rKeyFilter = getAliasInternalIdFilter(query, rAlias);
      // If one filtering key is specified, just return the duo with no roles
      if (lKeyFilter || rKeyFilter) {
        return [
          { alias: lAlias, internalIdKey: lKeyFilter },
          { alias: rAlias, internalIdKey: rKeyFilter },
        ];
      }
      return [
        { role: roleForLeft.trim(), alias: lAlias },
        { role: roleForRight.trim(), alias: rAlias },
      ];
    }, relationsVars)
  );
  return map((v) => {
    const associatedRole = Rfind((r) => r.alias === v.alias, roles);
    return pipe(
      assoc('internalIdKey', associatedRole ? associatedRole.internalIdKey : v.internalIdKey),
      assoc('role', associatedRole ? associatedRole.role : undefined)
    )(v);
  }, varWithKey);
};
// endregion

// region Loader common
export const querySubTypes = async (type, includeParents = false) => {
  return executeRead(async (rTx) => {
    const query = `match $x sub ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] querySubTypes`, { query });
    const iterator = await rTx.query(query);
    const answers = await iterator.collect();
    const result = await Promise.all(
      answers.map(async (answer) => {
        const subType = answer.map().get('x');
        const subTypeLabel = await subType.label();
        return {
          id: subType.id,
          label: subTypeLabel,
        };
      })
    );
    const sortByLabel = sortBy(compose(toLower, prop('label')));
    const finalResult = pipe(
      filter((n) => n.label !== type && (includeParents || !isAbstract(n.label))),
      sortByLabel,
      map((n) => ({ node: n }))
    )(result);
    return buildPagination(5000, 0, finalResult, 5000);
  });
};
export const queryAttributeValues = async (type) => {
  return executeRead(async (rTx) => {
    const query = `match $x isa ${escape(type)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValues`, { query });
    const iterator = await rTx.query(query);
    const answers = await iterator.collect();
    const result = await Promise.all(
      answers.map(async (answer) => {
        const attribute = answer.map().get('x');
        const attributeType = await attribute.type();
        const value = await attribute.value();
        const attributeTypeLabel = await attributeType.label();
        const replacedValue = typeof value === 'string' ? value.replace(/\\"/g, '"').replace(/\\\\/g, '\\') : value;
        return {
          node: {
            id: attribute.id,
            type: attributeTypeLabel,
            value: replacedValue,
          },
        };
      })
    );
    return buildPagination(5000, 0, result, 5000);
  });
};
export const attributeExists = async (attributeLabel) => {
  return executeRead(async (rTx) => {
    const checkQuery = `match $x sub ${attributeLabel}; get;`;
    logger.debug(`[GRAKN - infer: false] attributeExists`, { query: checkQuery });
    await rTx.query(checkQuery);
    return true;
  }).catch(() => false);
};
export const queryAttributeValueByGraknId = async (id) => {
  return executeRead(async (rTx) => {
    const query = `match $x id ${escape(id)}; get;`;
    logger.debug(`[GRAKN - infer: false] queryAttributeValueById`, { query });
    const iterator = await rTx.query(query);
    const answer = await iterator.next();
    const attribute = answer.map().get('x');
    const attributeType = await attribute.type();
    const value = await attribute.value();
    const attributeTypeLabel = await attributeType.label();
    const replacedValue = value.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    return {
      id: attribute.id,
      type: attributeTypeLabel,
      value: replacedValue,
    };
  });
};
/**
 * Load any grakn instance with internal grakn ID.
 * @param tx the transaction
 * @param concept the concept to get attributes from
 * @param args
 * @returns {Promise}
 */
const loadConcept = async (tx, concept, args = {}) => {
  const { internalId, relationsMap = new Map() } = args;
  const conceptBaseType = concept.baseType;
  // const types = await conceptTypes(tx, concept);
  const remoteConceptType = await concept.type();
  const conceptType = await remoteConceptType.label();
  const index = inferIndexFromConceptType(conceptType);
  // 01. Return the data in elastic if not explicitly asked in grakn
  // Very useful for getting every entities through relation query.
  if (useCache(args)) {
    const conceptFromCache = await elLoadById(internalId, null, relationsMap, [index]);
    if (!conceptFromCache) {
      /* istanbul ignore next */
      logger.info(`[ELASTIC] ${internalId} not indexed yet, loading with Grakn`);
    } else {
      return assoc('grakn_id', concept.id, conceptFromCache);
    }
  }
  // 02. If not found continue the process.
  logger.debug(`[GRAKN - infer: false] getAttributes ${conceptType} ${internalId}`);
  const attributesIterator = await concept.asRemote(tx).attributes();
  const attributes = await attributesIterator.collect();
  const attributesPromises = attributes.map(async (attribute) => {
    const attributeType = await attribute.type();
    const attributeLabel = await attributeType.label();
    return {
      dataType: await attributeType.dataType(),
      label: attributeLabel,
      value: await attribute.value(),
    };
  });
  return Promise.all(attributesPromises)
    .then((attributesData) => {
      const transform = pipe(
        map((attribute) => {
          let transformedVal = attribute.value;
          const { dataType, label } = attribute;
          if (dataType === GraknDate) {
            transformedVal = moment(attribute.value).utc().toISOString();
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
        assoc('_index', index),
        assoc('index_version', '1.0'),
        assoc('grakn_id', concept.id),
        assoc('id', transform.internal_id),
        assoc('base_type', conceptBaseType),
        assoc('parent_types', transform.entity_type ? getParentTypes(transform.entity_type) : null)
      )(transform);
    })
    .then(async (entityData) => {
      if (entityData.base_type !== BASE_TYPE_RELATION) return entityData;
      const isInferredPromise = concept.isInferred();
      const rolePlayers = await concept.asRemote(tx).rolePlayersMap();
      const roleEntries = Array.from(rolePlayers.entries());
      const rolesPromises = Promise.all(
        map(async (roleItem) => {
          const targetRole = last(roleItem).values().next();
          const remoteTargetType = await targetRole.value.type();
          const roleType = await remoteTargetType.label();
          // eslint-disable-next-line prettier/prettier
          return head(roleItem)
            .label()
            .then(async (roleLabel) => {
              const [, useAlias] = roleLabel.split('_');
              return {
                [useAlias]: null, // With be use lazily
                [`${useAlias}Id`]: args[`${useAlias}Id`],
                [`${useAlias}Role`]: roleLabel,
                [`${useAlias}Type`]: roleType,
              };
            });
        }, roleEntries)
      );
      // Wait for all promises before building the result
      return Promise.all([isInferredPromise, rolesPromises]).then(([isInferred, roles]) => {
        return pipe(
          assoc('id', entityData.id),
          assoc('inferred', isInferred),
          assoc('entity_type', entityData.entity_type),
          mergeRight(mergeAll(roles))
        )(entityData);
      });
    })
    .then((relationData) => {
      // Then change the id if relation is inferred
      if (relationData.inferred) {
        const { fromId, fromRole, toId, toRole } = relationData;
        const type = relationData.entity_type;
        const pattern = `{ $${INFERRED_RELATION_KEY}(${fromRole}: $from, ${toRole}: $to) isa ${type}; $from id ${fromId}; $to id ${toId}; };`;
        return pipe(
          assoc('id', Buffer.from(pattern).toString('base64')),
          assoc('internal_id', Buffer.from(pattern).toString('base64')),
          assoc('created', now()),
          assoc('modified', now()),
          assoc('created_at', now()),
          assoc('updated_at', now())
        )(relationData);
      }
      return relationData;
    });
};
// endregion

// region Loader list
const getSingleValue = (query, infer = false) => {
  return executeRead(async (rTx) => {
    logger.debug(`[GRAKN - infer: ${infer}] getSingleValue`, { query });
    const iterator = await rTx.query(query, { infer });
    return iterator.next();
  });
};
export const getSingleValueNumber = (query, infer = false) => {
  return getSingleValue(query, infer).then((data) => data.number());
};
const getConcepts = async (tx, answers, conceptQueryVars, entities, conceptOpts = {}) => {
  const { infer = false, noCache = false } = conceptOpts;
  const plainEntities = filter((e) => !isEmpty(e) && !isNil(e), entities);
  if (answers.length === 0) return [];
  // 02. Query concepts and rebind the data
  const queryConcepts = await Promise.all(
    map(async (answer) => {
      // Create a map useful for relation roles binding
      const queryVarsToConcepts = await Promise.all(
        conceptQueryVars.map(async ({ alias, role, internalIdKey }) => {
          const concept = answer.map().get(alias);
          if (!concept || concept.baseType === 'ATTRIBUTE') return undefined; // If specific attributes are used for filtering, ordering, ...
          // If internal id of the element is not directly accessible
          // And the element is part of element needed for the result, ensure the key is asked in the query.
          let conceptInternalId = internalIdKey;
          if (concept._inferred !== true && !conceptInternalId && includes(alias, plainEntities)) {
            const conceptInternalIdVar = answer.map().get(`${alias}_id`);
            if (!conceptInternalIdVar) {
              throw DatabaseError(`Query must ask for ${alias}_id`, { conceptQueryVars });
            }
            conceptInternalId = conceptInternalIdVar.value();
          }
          // Do the same for the from and the to
          let toInternalId;
          let fromInternalId;
          if (concept._inferred !== true && includes(alias, plainEntities) && concept.baseType === 'RELATION') {
            const fromVar = answer.map().get(`${alias}_from_id`);
            if (!fromVar) {
              throw DatabaseError(`Query must ask for ${alias}_from_id`);
            }
            fromInternalId = fromVar.value();
            const toVar = answer.map().get(`${alias}_to_id`);
            if (!toVar) {
              throw DatabaseError(`Query must ask for ${alias}_to_id`);
            }
            toInternalId = toVar.value();
          }
          const conceptType = await concept.type();
          const type = await conceptType.label();
          return {
            id: concept.id,
            internalId: conceptInternalId,
            fromInternalId,
            toInternalId,
            data: { concept, alias, role, internalIdKey, type },
          };
        })
      );
      const conceptsIndex = filter((e) => e, queryVarsToConcepts);
      const fetchingConceptsPairs = map((x) => [x.id, x.data], conceptsIndex);
      const relationsMap = new Map(fetchingConceptsPairs);
      // Fetch every concepts of the answer
      const requestedConcepts = filter((r) => includes(r.data.alias, entities), conceptsIndex);
      return map((t) => {
        const { concept } = t.data;
        return {
          internalId: t.internalId,
          fromId: t.fromInternalId,
          toId: t.toInternalId,
          concept,
          relationsMap,
        };
      }, requestedConcepts);
    }, answers)
  );
  // 03. Fetch every unique concepts
  const uniqConceptsLoading = pipe(
    flatten,
    uniqBy((e) => e.internalId),
    map((l) =>
      loadConcept(tx, l.concept, {
        internalId: l.internalId,
        fromId: l.fromId,
        toId: l.toId,
        relationsMap: l.relationsMap,
        noCache,
        infer,
      })
    )
  )(queryConcepts);
  const resolvedConcepts = await Promise.all(uniqConceptsLoading);
  // 04. Create map from concepts
  const conceptCache = new Map(map((c) => [c.grakn_id, c], resolvedConcepts));
  // 05. Bind all row to data entities
  const result = answers.map((answer) => {
    const dataPerEntities = plainEntities.map((entity) => {
      const concept = answer.map().get(entity);
      const conceptData = concept && conceptCache.get(concept.id);
      return [entity, conceptData];
    });
    return fromPairs(dataPerEntities);
  });
  // 06. Filter every relation in double
  // Grakn can respond with twice the relations (browse in 2 directions)
  if (result.length > 0) {
    const firstResult = head(result);
    const relationTargets = filter((elem) => elem && elem.base_type === 'RELATION', firstResult);
    if (!isEmpty(relationTargets)) {
      return uniqBy((u) => u[head(Object.keys(relationTargets))].internal_id, result);
    }
  }
  return result;
};
export const find = async (query, entities, findOpts = {}) => {
  // Remove empty values from entities
  const { infer = false } = findOpts;
  return executeRead(async (rTx) => {
    const conceptQueryVars = extractQueryVars(query);
    logger.debug(`[GRAKN - infer: ${infer}] Find`, { query });
    const iterator = await rTx.query(query, { infer });
    // 01. Get every concepts to fetch (unique)
    const answers = await iterator.collect();
    return getConcepts(rTx, answers, conceptQueryVars, entities, findOpts);
  });
};
// TODO Start - Refactor UI to be able to remove these 2 API
export const findWithConnectedRelations = async (query, key, options = {}) => {
  const { extraRelKey = null } = options;
  const dataFind = await find(query, [key, extraRelKey], options);
  return map((t) => ({ node: t[key], relation: t[extraRelKey] }), dataFind);
};
export const loadWithConnectedRelations = (query, key, options = {}) => {
  return findWithConnectedRelations(query, key, options).then((result) => head(result));
};
const listElements = async (
  baseQuery,
  first,
  offset,
  orderBy,
  orderMode,
  queryKey,
  connectedReference,
  inferred,
  noCache
) => {
  const countQuery = `${baseQuery} count;`;
  const paginateQuery = `offset ${offset}; limit ${first};`;
  const orderQuery = orderBy ? `sort $order ${orderMode};` : '';
  const query = `${baseQuery} ${orderQuery} ${paginateQuery}`;
  const countPromise = getSingleValueNumber(countQuery, inferred);
  const instancesPromise = await findWithConnectedRelations(query, queryKey, {
    extraRelKey: connectedReference,
    infer: inferred,
    noCache,
  });
  return Promise.all([instancesPromise, countPromise]).then(([instances, globalCount]) => {
    return buildPagination(first, offset, instances, globalCount);
  });
};
export const listEntities = async (entityTypes, searchFields, args = {}) => {
  // filters contains potential relations like, mitigates, tagged ...
  const { first = 1000, after, orderBy, orderMode = 'asc' } = args;
  const { search, filters } = args;
  const offset = after ? cursorToOffset(after) : 0;
  const isRelationOrderBy = orderBy && includes('.', orderBy);

  // Define if Elastic can support this query.
  // 01-2 Check the filters
  const validFilters = filter((f) => f && f.values.filter((n) => n).length > 0, filters || []);
  const unSupportedRelations =
    filter((k) => {
      // If the relation must be forced in a specific direction, ES cant support it.
      if (k.fromRole || k.toRole) return true;
      const isRelationFilter = includes('.', k.key);
      if (isRelationFilter) {
        // ES only support internal_id reference
        const [, field] = k.key.split('.');
        if (field !== 'internal_id') return true;
      }
      return false;
    }, validFilters).length > 0;
  // 01-3 Check the ordering
  const unsupportedOrdering = isRelationOrderBy && last(orderBy.split('.')) !== 'internal_id';
  const supportedByCache = !unsupportedOrdering && !unSupportedRelations;
  if (useCache(args) && supportedByCache) {
    return elPaginate(ENTITIES_INDICES, assoc('types', entityTypes, args));
  }
  logger.debug(`[GRAKN] ListEntities on Grakn, supportedByCache: ${supportedByCache}`);

  // 02. If not go with standard Grakn
  const relationsFields = [];
  const attributesFields = [];
  const attributesFilters = [];
  // Handle order by field
  if (isRelationOrderBy) {
    const [relation, field] = orderBy.split('.');
    const curatedRelation = relation.replace(REL_INDEX_PREFIX, '');
    relationsFields.push(
      `($elem, $${curatedRelation}) isa ${curatedRelation}; $${curatedRelation} has ${field} $order;`
    );
  } else if (orderBy) {
    attributesFields.push(`$elem has ${orderBy} $order;`);
  }
  // Handle filters
  if (validFilters && validFilters.length > 0) {
    for (let index = 0; index < validFilters.length; index += 1) {
      const filterKey = validFilters[index].key;
      const filterValues = validFilters[index].values;
      const isRelationFilter = includes('.', filterKey);
      if (isRelationFilter) {
        const [relation, field] = filterKey.split('.');
        const curatedRelation = relation.replace(REL_INDEX_PREFIX, '');
        const sourceRole = validFilters[index].fromRole ? `${validFilters[index].fromRole}:` : '';
        const toRole = validFilters[index].toRole ? `${validFilters[index].toRole}:` : '';
        const relId = `rel_${curatedRelation}`;
        relationsFields.push(`$${relId} (${sourceRole}$elem, ${toRole}$${curatedRelation}) isa ${curatedRelation};`);
        for (let valueIndex = 0; valueIndex < filterValues.length; valueIndex += 1) {
          // Apply filter on target.
          const val = filterValues[valueIndex];
          const preparedValue = Rtype(val) === 'Boolean' ? val : `"${escapeString(val)}"`;
          // TODO @Julien Support more than only boolean and string filters
          attributesFields.push(`$${curatedRelation} has ${field} ${preparedValue};`);
        }
      } else {
        for (let valueIndex = 0; valueIndex < filterValues.length; valueIndex += 1) {
          const val = filterValues[valueIndex];
          if (val === 'EXISTS') {
            attributesFields.push(`$elem has ${filterKey} $${filterKey}_exist;`);
          } else {
            const preparedValue = Rtype(val) === 'Boolean' ? val : `"${escapeString(val)}"`;
            attributesFields.push(`$elem has ${filterKey} ${preparedValue};`);
          }
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
      map((e) => `{ $${e} contains "${escapeString(search)}"; }`),
      join(' or ')
    )(searchFields);
    attributesFilters.push(`${searchFilter};`);
  }
  // build the final query
  const queryAttributesFields = join(' ', attributesFields);
  const queryAttributesFilters = join(' ', attributesFilters);
  const queryRelationsFields = join(' ', relationsFields);
  const headType = entityTypes.length === 1 ? head(entityTypes) : 'Basic-Object';
  const extraTypes =
    entityTypes.length > 1
      ? pipe(
          map((e) => `{ $elem isa ${e}; }`),
          join(' or '),
          concat(__, ';')
        )(entityTypes)
      : '';
  const baseQuery = `match $elem isa ${headType}, has internal_id $elem_id; ${extraTypes} ${queryRelationsFields} 
                      ${queryAttributesFields} ${queryAttributesFilters} get;`;
  return listElements(baseQuery, first, offset, orderBy, orderMode, 'elem', null, false, args.noCache);
};
export const listRelations = async (relationshipType, args) => {
  const searchFields = ['name', 'description'];
  const { first = 1000, after, orderBy, orderMode = 'asc', relationFilter, inferred = false } = args;
  let useInference = inferred;
  const { filters = [], search, fromId, fromRole, toId, toRole, fromTypes = [], toTypes = [] } = args;
  const { startTimeStart, startTimeStop, stopTimeStart, stopTimeStop, confidences = [] } = args;

  // Use $from, $to only if fromId or toId specified.
  // Else, just ask for the relation only.
  // fromType or toType only allow if fromId or toId available
  const definedRoles = !isNil(fromRole) || !isNil(toRole);
  const haveTargetFilters = filters && filters.length > 0; // For now filters only contains target to filtering
  const fromTypesFilter = fromTypes && fromTypes.length > 0;
  const toTypesFilter = toTypes && toTypes.length > 0;

  const offset = after ? cursorToOffset(after) : 0;
  const isRelationOrderBy = orderBy && includes('.', orderBy);
  // Handle relation type(s)
  const relationToGet = relationshipType || 'stix-core-relationship';
  // 0 - Check if we can support the query by Elastic
  const unsupportedOrdering = isRelationOrderBy && last(orderBy.split('.')) !== 'internal_id';
  // Search is not supported because its only search on the relation to.
  const supportedByCache = !search && !unsupportedOrdering && !haveTargetFilters && !inferred && !definedRoles;
  if (useCache(args) && supportedByCache) {
    const finalFilters = [];
    if (relationFilter) {
      const { relation, id, relationId } = relationFilter;
      finalFilters.push({ key: `${REL_INDEX_PREFIX}${relation}.internal_id`, values: [id] });
      if (relationId) {
        finalFilters.push({ key: `internal_id`, values: [relationId] });
      }
    }
    const relationsMap = new Map();
    if (fromId) {
      finalFilters.push({ key: 'connections.internal_id', values: [fromId] });
      relationsMap.set(fromId, { alias: 'from', internalIdKey: fromId });
    }
    if (toId) {
      finalFilters.push({ key: 'connections.internal_id', values: [toId] });
      relationsMap.set(toId, { alias: 'to', internalIdKey: toId });
    }
    if (fromTypes && fromTypes.length > 0) finalFilters.push({ key: 'connections.types', values: fromTypes });
    if (toTypes && toTypes.length > 0) finalFilters.push({ key: 'connections.types', values: toTypes });
    if (startTimeStart) finalFilters.push({ key: 'start_time', values: [startTimeStart], operator: 'gt' });
    if (startTimeStop) finalFilters.push({ key: 'start_time', values: [startTimeStop], operator: 'lt' });
    if (stopTimeStart) finalFilters.push({ key: 'stop_time', values: [stopTimeStart], operator: 'gt' });
    if (stopTimeStop) finalFilters.push({ key: 'stop_time', values: [stopTimeStop], operator: 'lt' });
    if (confidences && confidences.length > 0) finalFilters.push({ key: 'confidence', values: confidences });
    const paginateArgs = pipe(
      assoc('types', [relationToGet]),
      assoc('filters', finalFilters),
      assoc('relationsMap', relationsMap)
    )(args);
    return elPaginate(RELATIONSHIPS_INDICES, paginateArgs);
  }
  // 1- If not, use Grakn
  const queryFromTypes = fromTypesFilter
    ? pipe(
        map((e) => `{ $from isa ${e}; }`),
        join(' or '),
        concat(__, ';')
      )(fromTypes)
    : '';
  const queryToTypes = toTypesFilter
    ? pipe(
        map((e) => `{ $to isa ${e}; }`),
        join(' or '),
        concat(__, ';')
      )(toTypes)
    : '';
  // Search
  const relationsFields = [];
  const attributesFields = [];
  const attributesFilters = [];
  // Handle order by field
  if (isRelationOrderBy) {
    const [relation, field] = orderBy.split('.');
    const curatedRelation = relation.replace(REL_INDEX_PREFIX, '');
    if (curatedRelation.includes(REL_CONNECTED_SUFFIX)) {
      const finalCuratedRelation = curatedRelation.replace(REL_CONNECTED_SUFFIX, '');
      relationsFields.push(`$${finalCuratedRelation} has ${field} $order;`);
    } else {
      useInference = true;
      relationsFields.push(
        `($rel, $${curatedRelation}) isa ${curatedRelation}; $${curatedRelation} has ${field} $order;` +
          `not { ($rel, $compare) isa ${curatedRelation}; $compare has ${field} $conn-order; $conn-order > $order; };`
      );
    }
  } else if (orderBy) {
    attributesFields.push(`$rel has ${orderBy} $order;`);
  }
  // Handle every filters
  if (search) {
    for (let searchIndex = 0; searchIndex < searchFields.length; searchIndex += 1) {
      const searchFieldName = searchFields[searchIndex];
      attributesFields.push(`$to has ${searchFieldName} $${searchFieldName};`);
    }
    const searchFilter = pipe(
      map((e) => `{ $${e} contains "${escapeString(search)}"; }`),
      join(' or ')
    )(searchFields);
    attributesFilters.push(`${searchFilter};`);
  }
  if (fromId) attributesFilters.push(`$from has internal_id "${escapeString(fromId)}";`);
  if (toId) attributesFilters.push(`$to has internal_id "${escapeString(toId)}";`);
  if (startTimeStart || startTimeStop) {
    attributesFields.push(`$rel has start_time $fs;`);
    if (startTimeStart) attributesFilters.push(`$fs > ${prepareDate(startTimeStart)};`);
    if (startTimeStop) attributesFilters.push(`$fs < ${prepareDate(startTimeStop)};`);
  }
  if (stopTimeStart || stopTimeStop) {
    attributesFields.push(`$rel has stop_time $ls;`);
    if (stopTimeStart) attributesFilters.push(`$ls > ${prepareDate(stopTimeStart)};`);
    if (stopTimeStop) attributesFilters.push(`$ls < ${prepareDate(stopTimeStop)};`);
  }
  if (confidences && confidences.length > 0) {
    attributesFields.push(`$rel has confidence $confidence;`);
    // eslint-disable-next-line prettier/prettier
    attributesFilters.push(
      pipe(
        map((e) => `{ $confidence == ${e}; }`),
        join(' or '),
        concat(__, ';')
      )(confidences)
    );
  }
  const relationRef = relationFilter ? 'relationRef' : null;
  if (relationFilter) {
    // eslint-disable-next-line no-shadow
    const { relation, fromRole: fromRoleFilter, toRole: toRoleFilter, id, relationId } = relationFilter;
    const pEid = escapeString(id);
    const relationQueryPart = `$${relationRef}(${fromRoleFilter}:$rel, ${toRoleFilter}:$pointer) isa ${relation}, has internal_id $${relationRef}_id;
    $rel has internal_id ${fromRoleFilter.includes('_from') ? `$${relationRef}_from_id` : `$${relationRef}_to_id`};
    $pointer has internal_id ${toRoleFilter.includes('_to') ? `$${relationRef}_to_id` : `$${relationRef}_from_id`};
    $pointer has internal_id "${pEid}";`;
    relationsFields.push(relationQueryPart);
    if (relationId) {
      attributesFilters.push(`$rel has internal_id "${escapeString(relationId)}";`);
    }
  }
  if (filters.length > 0) {
    // eslint-disable-next-line
    for (const f of filters) {
      if (!includes(REL_CONNECTED_SUFFIX, f.key)) {
        throw FunctionalError('Filters only support connected target filtering');
      }
      // eslint-disable-next-line prettier/prettier
      const filterKey = f.key.replace(REL_INDEX_PREFIX, '').replace(REL_CONNECTED_SUFFIX, '').split('.');
      const [key, val] = filterKey;
      const queryFilters = pipe(
        map((e) => `{ $${key} has ${val} ${f.operator === 'match' ? 'contains' : ''} "${escapeString(e)}"; }`),
        join(' or '),
        concat(__, ';')
      )(f.values);
      attributesFilters.push(queryFilters);
    }
  }
  // Build the query
  const queryAttributesFields = join(' ', attributesFields);
  const queryAttributesFilters = join(' ', attributesFilters);
  const queryRelationsFields = join(' ', relationsFields);
  const fromRoleQuery =
    // eslint-disable-next-line no-nested-ternary
    fromRole && fromRole.length > 0 ? `${fromRole}:` : isAbstract(relationToGet) ? '' : `${relationToGet}_from:`;
  const toRoleQuery =
    // eslint-disable-next-line no-nested-ternary
    toRole && toRole.length > 0 ? `${toRole}:` : isAbstract(relationToGet) ? '' : `${relationToGet}_to:`;
  const baseQuery = `match $rel(${fromRoleQuery}$from, ${toRoleQuery}$to) isa ${relationToGet}, has internal_id $rel_id; 
  $from has internal_id $rel_from_id; 
  $to has internal_id $rel_to_id; 
  ${queryFromTypes} ${queryToTypes} ${queryRelationsFields} ${queryAttributesFields} ${queryAttributesFilters} get;`;
  return listElements(baseQuery, first, offset, orderBy, orderMode, 'rel', relationRef, useInference, args.noCache);
};
// endregion

// region Loader element
export const load = async (query, entities, options) => {
  const data = await find(query, entities, options);
  if (data.length > 1) {
    logger.debug('[GRAKN] Maybe you should use list instead for multiple results', { query });
  }
  return head(data);
};
const internalLoadEntityByStixId = async (id, args = {}) => {
  const { type } = args;
  if (useCache(args)) return elLoadByStixId(id, type);
  const stixId = `${escapeString(id)}`;
  const query = `match $x isa ${type || 'thing'}; $x has internal_id $x_id;
  { $x has standard_id "${stixId}";} or { $x has stix_ids "${stixId}";}; get;`;
  const element = await load(query, ['x'], args);
  return element ? element.x : null;
};
export const internalLoadEntityById = async (id, args = {}) => {
  const { type } = args;
  if (isStixId(id)) return internalLoadEntityByStixId(id, args);
  if (useCache(args)) return elLoadById(id, type);
  const query = `match $x isa ${type || 'thing'}; $x has internal_id "${escapeString(id)}"; get;`;
  const element = await load(query, ['x'], args);
  return element ? element.x : null;
};
export const loadEntityById = async (id, type, args = {}) => {
  if (isNil(type)) throw FunctionalError(`You need to specify a type when loading an entity (id)`);
  return internalLoadEntityById(id, assoc('type', type, args));
};
const loadRelationByStixId = async (id, type, args = {}) => {
  if (isNil(type)) throw FunctionalError(`You need to specify a type when loading a relation (stix)`);
  if (useCache(args)) return elLoadByStixId(id);
  const eid = escapeString(id);
  const query = `match $rel($from, $to) isa ${type}; { $rel has internal_id "${eid}"; } 
  or { $rel has standard_id "${eid}"; }
  or { $rel has stix_ids "${eid}";};
  $rel has internal_id $rel_id;
  $from has internal_id $rel_from_id;
  $to has internal_id $rel_to_id;
  get;`;
  const element = await load(query, ['rel'], args);
  return element ? element.rel : null;
};
export const loadRelationById = async (id, type, args = {}) => {
  if (isNil(type)) throw FunctionalError(`You need to specify a type when loading a relation (id)`);
  if (isStixId(id)) return loadRelationByStixId(id, type, args);
  if (useCache(args)) return elLoadById(id, type);
  const eid = escapeString(id);
  const query = `match $rel($from, $to) isa ${type}, has internal_id "${eid}";
  $rel has internal_id $rel_id;
  $from has internal_id $rel_from_id;
  $to has internal_id $rel_to_id;
  get;`;
  const element = await load(query, ['rel'], args);
  return element ? element.rel : null;
};
export const loadById = async (id, type, args = {}) => {
  if (useCache(args)) return elLoadById(id);
  if (isBasicObject(type)) return loadEntityById(id, type, args);
  if (isBasicRelationship(type)) return loadRelationById(id, type, args);
  throw FunctionalError(`Type ${type} is unknown.`);
};
// endregion

// region Indexer
export const reindexAttributeValue = async (queryType, type, value) => {
  const index = inferIndexFromConceptType(queryType);
  const readQuery = `match $x isa ${queryType}, has ${escape(type)} $a, has internal_id $x_id; $a "${escapeString(
    value
  )}"; get;`;
  logger.debug(`[GRAKN - infer: false] attributeUpdate`, { query: readQuery });
  const elementIds = await executeRead(async (rTx) => {
    const iterator = await rTx.query(readQuery, { infer: false });
    const answer = await iterator.collect();
    return answer.map((n) => n.get('x_id').value());
  });
  let body;
  if (includes(type, multipleAttributes)) {
    body = elementIds.flatMap((id) => [{ update: { _index: index, _id: id } }, { doc: { [type]: [value] } }]);
  } else {
    body = elementIds.flatMap((id) => [{ update: { _index: index, _id: id } }, { doc: { [type]: value } }]);
  }
  if (body.length > 0) {
    await elBulk({ refresh: true, body });
  }
};
// endregion

// region Graphics
const buildAggregationQuery = (entityType, filters, options) => {
  const { operation, field, interval, startDate, endDate } = options;
  let baseQuery = `match $from isa ${entityType}; ${startDate || endDate ? `$from has ${field} $created;` : ''}`;
  if (startDate) baseQuery = `${baseQuery} $created > ${prepareDate(startDate)};`;
  if (endDate) baseQuery = `${baseQuery} $created < ${prepareDate(endDate)};`;
  const filterQuery = pipe(
    map((filterElement) => {
      const { isRelation, value, start, end, type } = filterElement;
      const eValue = `${escapeString(value)}`;
      if (isRelation) {
        const fromRole = `${type}_from`;
        const toRole = `${type}_to`;
        const dateRange =
          start && end
            ? `$rel_${type} has start_time $fs; $fs > ${prepareDate(start)}; $fs < ${prepareDate(end)};`
            : '';
        const relation = `$rel_${type}(${fromRole}:$from, ${toRole}:$${type}_to) isa ${type};`;
        return `${relation} ${dateRange} $${type}_to has internal_id "${eValue}";`;
      }
      return `$from has ${type} "${eValue}";`;
    }),
    join('')
  )(filters);
  const groupField = interval ? `${field}_${interval}` : field;
  const groupingQuery = `$from has ${groupField} $g; get; group $g; ${operation};`;
  return `${baseQuery} ${filterQuery} ${groupingQuery}`;
};
const graknTimeSeries = (query, keyRef, valueRef, inferred) => {
  return executeRead(async (rTx) => {
    logger.debug(`[GRAKN - infer: ${inferred}] timeSeries`, { query });
    const iterator = await rTx.query(query, { infer: inferred });
    const answer = await iterator.collect();
    return Promise.all(
      answer.map(async (n) => {
        const owner = await n.owner().value();
        const value = await n.answers()[0].number();
        return { [keyRef]: owner, [valueRef]: value };
      })
    );
  });
};
export const timeSeriesEntities = async (entityType, filters, options) => {
  // filters: [ { isRelation: true, type: stix_relation, value: uuid } ]
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, operation, field, interval, noCache = false, inferred = false } = options;
  // Check if can be supported by ES
  let histogramData;
  if (!noCache && operation === 'count' && !inferred) {
    histogramData = await elHistogramCount(entityType, field, interval, startDate, endDate, filters);
  } else {
    // If not compatible, do it with grakn
    const finalQuery = buildAggregationQuery(entityType, filters, options);
    histogramData = await graknTimeSeries(finalQuery, 'date', 'value', inferred);
  }
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const timeSeriesRelations = async (options) => {
  // filters: [ { isRelation: true, type: stix_relation, value: uuid }
  //            { isRelation: false, type: report_class, value: string } ]
  const { startDate, endDate, operation, relationship_type: relationshipType, field, interval } = options;
  const { fromId, noCache = false, inferred = false } = options;
  // Check if can be supported by ES
  let histogramData;
  const entityType = relationshipType ? escape(relationshipType) : 'stix-relationship';
  if (!noCache && operation === 'count' && inferred === false) {
    const filters = [];
    if (fromId) filters.push({ isRelation: false, type: 'connections.internal_id', value: fromId });
    histogramData = await elHistogramCount(entityType, field, interval, startDate, endDate, filters);
  } else {
    const query = `match $x ${fromId ? '($from)' : ''} isa ${entityType}; ${
      fromId ? `$from has internal_id "${escapeString(fromId)}";` : ''
    }`;
    const finalQuery = `${query} $x has ${field}_${interval} $g; get; group $g; ${operation};`;
    histogramData = await graknTimeSeries(finalQuery, 'date', 'value', inferred);
  }
  return fillTimeSeries(startDate, endDate, interval, histogramData);
};
export const distributionEntities = async (entityType, filters = [], options) => {
  // filters: { isRelation: true, type: stix_relation, start: date, end: date, value: uuid }
  const { noCache = false, inferred = false, limit = 10, order = 'asc' } = options;
  const { startDate, endDate, field, operation } = options;
  let distributionData;
  // Unsupported in cache: const { isRelation, value, from, to, start, end, type };
  if (field.includes('.')) {
    throw FunctionalError('Distribution entities doesnt support relation aggregation field');
  }
  const supportedFilters = filter((f) => f.start || f.end || f.from || f.to, filters).length === 0;
  if (!noCache && operation === 'count' && supportedFilters && inferred === false) {
    distributionData = await elAggregationCount(entityType, field, startDate, endDate, filters);
  } else {
    const finalQuery = buildAggregationQuery(entityType, filters, options);
    distributionData = await graknTimeSeries(finalQuery, 'label', 'value', inferred);
  }
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? ascend : descend;
  return take(limit, sortWith([orderingFunction(prop('value'))])(distributionData));
};
export const distributionRelations = async (options) => {
  const { fromId, field, operation } = options; // Mandatory fields
  const { limit = 50, order, noCache = false, inferred = false } = options;
  const { startDate, endDate, relationship_type: relationshipType, toTypes = [] } = options;
  let distributionData;
  const entityType = relationshipType ? escape(relationshipType) : ABSTRACT_STIX_RELATIONSHIP;
  // Using elastic can only be done if the distribution is a count on types
  if (!noCache && field === 'entity_type' && operation === 'count' && inferred === false) {
    distributionData = await elAggregationRelationsCount(entityType, startDate, endDate, toTypes, fromId);
  } else {
    const query = `match $rel($from, $to) isa ${entityType}; ${
      toTypes && toTypes.length > 0
        ? `${join(
            ' ',
            map((toType) => `{ $to isa ${escape(toType)}; } or`, toTypes)
          )} { $to isa ${escape(head(toTypes))}; };`
        : ''
    } $from has internal_id "${escapeString(fromId)}";
    ${
      startDate && endDate
        ? `$rel has start_time $fs; $fs > ${prepareDate(startDate)}; $fs < ${prepareDate(endDate)};`
        : ''
    }
      $to has ${escape(field)} $g; get; group $g; ${escape(operation)};`;
    distributionData = await graknTimeSeries(query, 'label', 'value', inferred);
  }
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? ascend : descend;
  return take(limit, sortWith([orderingFunction(prop('value'))])(distributionData));
};
export const distributionEntitiesThroughRelations = async (options) => {
  const { limit = 10, order, inferred = false } = options;
  const { relationshipType, remoteRelationshipType, toType, fromId, field, operation } = options;
  let query = `match $rel($from, $to) isa ${relationshipType}; $to isa ${toType};`;
  query += `$from has internal_id "${escapeString(fromId)}";`;
  query += `$rel2($to, $to2) isa ${remoteRelationshipType};`;
  query += `$to2 has ${escape(field)} $g; get; group $g; ${escape(operation)};`;
  const distributionData = await graknTimeSeries(query, 'label', 'value', inferred);
  // Take a maximum amount of distribution depending on the ordering.
  const orderingFunction = order === 'asc' ? ascend : descend;
  return take(limit, sortWith([orderingFunction(prop('value'))])(distributionData));
};
// endregion

// region mutation common
const prepareAttribute = (value) => {
  // Attribute is coming from GraphQL
  if (value instanceof Date) return prepareDate(value);
  // Attribute is coming from internal
  if (Date.parse(value) > 0 && new Date(value).toISOString() === value) return prepareDate(value);
  // TODO Delete that
  if (/^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d\.\d+([+-][0-2]\d:[0-5]\d|Z)$/.test(value))
    return prepareDate(value);
  if (/^\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\dZ$/.test(value)) return prepareDate(value);
  if (typeof value === 'string') return `"${escapeString(value)}"`;
  return escape(value);
};
const flatAttributesForObject = (data) => {
  const elements = Object.entries(data);
  return pipe(
    map((elem) => {
      const key = head(elem);
      const value = last(elem);
      if (Array.isArray(value)) {
        return map((iter) => ({ key, value: iter }), value);
      }
      // Some dates needs to detailed for search
      if (value && includes(key, statsDateAttributes)) {
        return [
          { key, value },
          { key: `${key}_day`, value: dayFormat(value) },
          { key: `${key}_month`, value: monthFormat(value) },
          { key: `${key}_year`, value: yearFormat(value) },
        ];
      }
      return { key, value };
    }),
    flatten,
    filter((f) => f.value !== undefined)
  )(elements);
};
// endregion

// region mutation relation
const createRelationRaw = async (user, input, opts = {}) => {
  const { fromId, toId, relationship_type: relationshipType } = input;
  const { noLog = false } = opts;
  // 01. First fix the direction of the relation
  if (!fromId || !toId) throw FunctionalError(`Relation without from or to`, { input });
  if (fromId === toId) {
    /* istanbul ignore next */
    throw FunctionalError(`You cant create a relation with the same source and target`, {
      from: input.fromId,
      relationshipType,
    });
  }
  // Check dependencies
  const fromRole = `${relationshipType}_from`;
  const toRole = `${relationshipType}_to`;
  const fromPromise = internalLoadEntityById(fromId);
  const toPromise = internalLoadEntityById(toId);
  const [from, to] = await Promise.all([fromPromise, toPromise]);
  if (!from || !to) {
    throw MissingReferenceError({ input, from, to });
  }
  // 03. Generate the ID
  const internalId = generateInternalId();
  const standardId = generateStandardId(
    relationshipType,
    pipe(assoc('fromId', from.standard_id), assoc('toId', to.standard_id))(input)
  );

  // 04. Prepare the relation to be created
  const today = now();
  let relationAttributes = {};
  // Default attributes
  // basic-relationship
  relationAttributes.internal_id = internalId;
  relationAttributes.standard_id = standardId;
  relationAttributes.entity_type = relationshipType;
  relationAttributes.created_at = today;
  relationAttributes.updated_at = today;
  // stix-relationship
  if (isStixRelationship(relationshipType)) {
    relationAttributes.stix_ids = isNil(input.stix_id) ? [] : [input.stix_id];
    relationAttributes.spec_version = STIX_SPEC_VERSION;
    relationAttributes.revoked = isNil(input.revoked) ? false : input.revoked;
    relationAttributes.confidence = isNil(input.confidence) ? 0 : input.confidence;
    relationAttributes.lang = isNil(input.lang) ? 'en' : input.lang;
    relationAttributes.created = isNil(input.created) ? today : input.created;
    relationAttributes.modified = isNil(input.modified) ? today : input.modified;
  }
  // stix-core-relationship
  if (isStixCoreRelationship(relationshipType)) {
    relationAttributes.relationship_type = relationshipType;
    relationAttributes.description = input.description ? input.description : '';
    relationAttributes.start_time = isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    /* istanbul ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with a start_time less than the stop_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-observable-relationship
  if (isStixCyberObservableRelationship(relationshipType)) {
    relationAttributes.relationship_type = relationshipType;
    relationAttributes.start_time = isNil(input.start_time) ? new Date(FROM_START) : input.start_time;
    relationAttributes.stop_time = isNil(input.stop_time) ? new Date(UNTIL_END) : input.stop_time;
    /* istanbul ignore if */
    if (relationAttributes.start_time > relationAttributes.stop_time) {
      throw DatabaseError('You cant create a relation with a start_time less than the stop_time', {
        from: input.fromId,
        input,
      });
    }
  }
  // stix-sighting-relationship
  if (isStixSightingRelationship(relationshipType)) {
    relationAttributes.description = isNil(input.description) ? '' : input.description;
    relationAttributes.attribute_count = isNil(input.attribute_count) ? 1 : input.attribute_count;
    relationAttributes.x_opencti_negative = isNil(input.x_opencti_negative) ? false : input.x_opencti_negative;
    relationAttributes.first_seen = isNil(input.first_seen) ? new Date(FROM_START) : input.first_seen;
    relationAttributes.last_seen = isNil(input.last_seen) ? new Date(UNTIL_END) : input.last_seen;
    /* istanbul ignore if */
    if (relationAttributes.first_seen > relationAttributes.last_seen) {
      throw DatabaseError('You cant create a relation with a first_seen less than the last_seen', {
        from: input.fromId,
        input,
      });
    }
  }
  // Add the additional fields for dates (day, month, year)
  const dataKeys = Object.keys(relationAttributes);
  for (let index = 0; index < dataKeys.length; index += 1) {
    // Adding dates elements
    if (includes(dataKeys[index], statsDateAttributes)) {
      const dayValue = dayFormat(relationAttributes[dataKeys[index]]);
      const monthValue = monthFormat(relationAttributes[dataKeys[index]]);
      const yearValue = yearFormat(relationAttributes[dataKeys[index]]);
      relationAttributes = pipe(
        assoc(`${dataKeys[index]}_day`, dayValue),
        assoc(`${dataKeys[index]}_month`, monthValue),
        assoc(`${dataKeys[index]}_year`, yearValue)
      )(relationAttributes);
    }
  }
  let lock;
  try {
    // Try to get the lock in redis
    lock = await lockResource(internalId);
    // 04. Create the relation
    await executeWrite(async (wTx) => {
      // Build final query
      let query = `match $from isa ${input.fromType ? input.fromType : 'thing'}; 
      $from has internal_id "${from.internal_id}"; 
      $to has internal_id "${to.internal_id}";
      insert $rel(${fromRole}: $from, ${toRole}: $to) isa ${relationshipType},`;
      const queryElements = flatAttributesForObject(relationAttributes);
      const nbElements = queryElements.length;
      for (let index = 0; index < nbElements; index += 1) {
        const { key, value } = queryElements[index];
        const insert = prepareAttribute(value);
        const separator = index + 1 === nbElements ? ';' : ',';
        query += `has ${key} ${insert}${separator} `;
      }
      logger.debug(`[GRAKN - infer: false] createRelation`, { query });
      const iterator = await wTx.query(query);
      const txRelation = await iterator.next();
      if (txRelation === null) {
        throw MissingReferenceError({ input });
      }
    });
  } catch (err) {
    if (err.name === TYPE_DUPLICATE_ENTRY) {
      logger.warn(err.message, { input, ...err.data });
      return loadRelationById(err.data.id, relationshipType);
    }
    // Lock cant be acquired after 5 sec, assume relation already exists.
    if (err.name === 'LockError') {
      throw DuplicateEntryError('Relation already exists (redis)', { id: internalId });
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
  // 05. Prepare the final data with Grakn IDs
  const createdRel = pipe(
    assoc('id', internalId),
    assoc('fromId', from.internal_id),
    assoc('fromRole', fromRole),
    assoc('fromType', from.entity_type),
    assoc('toId', to.internal_id),
    assoc('toRole', toRole),
    assoc('toType', to.entity_type),
    // Relation specific
    assoc('inferred', false),
    // Types
    assoc('entity_type', relationshipType),
    assoc('parent_types', getParentTypes(relationshipType)),
    assoc('base_type', BASE_TYPE_RELATION)
  )(relationAttributes);
  const postOperations = [];
  // 04. Index the relation and the modification in the base entity
  postOperations.push(elIndexElements([createdRel]));
  // 05. Send logs
  if (!noLog) {
    if (isStixMetaRelationship(relationshipType)) {
      const eventType = relationshipType === RELATION_CREATED_BY ? EVENT_TYPE_UPDATE : EVENT_TYPE_UPDATE_ADD;
      postOperations.push(sendLog(eventType, user, createdRel, { from, to }));
    } else {
      postOperations.push(sendLog(EVENT_TYPE_CREATE, user, createdRel, { from, to }));
    }
  }
  await Promise.all(postOperations);
  // 06. Return result if no need to reverse the relations from and to
  return createdRel;
};
const addCreatedBy = async (user, fromInternalId, createdById, opts = {}) => {
  if (!createdById) return undefined;
  const input = {
    fromId: fromInternalId,
    toId: createdById,
    relationship_type: RELATION_CREATED_BY,
  };
  return createRelationRaw(user, input, opts);
};
const addMarkingDef = async (user, fromInternalId, markingDefId, opts = {}) => {
  if (!markingDefId) return undefined;
  const input = {
    fromId: fromInternalId,
    toId: markingDefId,
    relationship_type: RELATION_OBJECT_MARKING,
  };
  return createRelationRaw(user, input, opts);
};
const addMarkingDefs = async (user, internalId, markingDefIds, opts = {}) => {
  if (!markingDefIds || isEmpty(markingDefIds)) return undefined;
  const markings = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < markingDefIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const marking = await addMarkingDef(user, internalId, markingDefIds[i], opts);
    markings.push(marking);
  }
  return markings;
};
const addLabel = async (user, fromInternalId, labelId, opts = {}) => {
  if (!labelId) return undefined;
  const input = {
    fromId: fromInternalId,
    toId: labelId,
    relationship_type: RELATION_OBJECT_LABEL,
  };
  return createRelationRaw(user, input, opts);
};
const addLabels = async (user, internalId, labelIds, opts = {}) => {
  if (!labelIds || isEmpty(labelIds)) return undefined;
  const labels = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < labelIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const tag = await addLabel(user, internalId, labelIds[i], opts);
    labels.push(tag);
  }
  return labels;
};
const addExternalReference = async (user, fromInternalId, externalReferenceId, opts = {}) => {
  if (!externalReferenceId) return undefined;
  const input = {
    fromId: fromInternalId,
    toId: externalReferenceId,
    relationship_type: RELATION_EXTERNAL_REFERENCE,
  };
  return createRelationRaw(user, input, opts);
};
const addExternalReferences = async (user, internalId, externalReferenceIds, opts = {}) => {
  if (!externalReferenceIds || isEmpty(externalReferenceIds)) return undefined;
  const externalReferences = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < externalReferenceIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const externalReference = await addExternalReference(user, internalId, externalReferenceIds[i], opts);
    externalReferences.push(externalReference);
  }
  return externalReferences;
};
const addKillChain = async (user, fromInternalId, killChainId, opts = {}) => {
  if (!killChainId) return undefined;
  const input = {
    fromId: fromInternalId,
    toId: killChainId,
    relationship_type: RELATION_KILL_CHAIN_PHASE,
  };
  return createRelationRaw(user, input, opts);
};
const addKillChains = async (user, internalId, killChainIds, opts = {}) => {
  if (!killChainIds || isEmpty(killChainIds)) return undefined;
  const killChains = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < killChainIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const killChain = await addKillChain(user, internalId, killChainIds[i], opts);
    killChains.push(killChain);
  }
  return killChains;
};
const addObject = async (user, fromInternalId, stixObjectId, opts = {}) => {
  if (!stixObjectId) return undefined;
  const input = {
    fromId: fromInternalId,
    toId: stixObjectId,
    relationship_type: RELATION_OBJECT,
  };
  return createRelationRaw(user, input, opts);
};
const addObjects = async (user, internalId, stixObjectIds, opts = {}) => {
  if (!stixObjectIds || isEmpty(stixObjectIds)) return undefined;
  const objects = [];
  // Relations cannot be created in parallel.
  for (let i = 0; i < stixObjectIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const object = await addObject(user, internalId, stixObjectIds[i], opts);
    objects.push(object);
  }
  return objects;
};
export const createRelation = async (user, input, opts = {}) => {
  let relation;
  try {
    relation = await createRelationRaw(user, input, opts);
  } catch (err) {
    if (err.name === TYPE_DUPLICATE_ENTRY) {
      logger.warn(err.message, { input, ...err.data });
      return loadRelationById(err.data.id, input.relationship_type);
    }
    throw err;
  }
  // Complete with eventual relations (will eventually update the index)
  await Promise.all([
    addCreatedBy(user, relation.id, input.createdBy, opts),
    addMarkingDefs(user, relation.id, input.markingDefinitions, opts),
    addKillChains(user, relation.id, input.killChainPhases, opts),
  ]);
  return relation;
};
/* istanbul ignore next */
export const createRelations = async (user, inputs, opts = {}) => {
  const createdRelations = [];
  // Relations cannot be created in parallel. (Concurrent indexing on same key)
  // Could be improve by grouping and indexing in one shot.
  for (let i = 0; i < inputs.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    const relation = await createRelation(user, inputs[i], opts);
    createdRelations.push(relation);
  }
  return createdRelations;
};
// endregion

// region mutation entity
export const createEntity = async (user, input, type, opts = {}) => {
  const { noLog = false } = opts;
  // We need to check existing dependencies
  // Except, Labels and KillChains that are embedded in same execution.
  const idsToResolve = [];
  if (input.createdBy) idsToResolve.push({ id: input.createdBy });
  forEach((marking) => idsToResolve.push({ id: marking }), input.markingDefinitions || []);
  forEach((object) => idsToResolve.push({ id: object }), input.objects || []);
  const elemPromise = (ref) => internalLoadEntityById(ref.id).then((e) => ({ ref, available: e !== null }));
  const checkIds = await Promise.all(map(elemPromise, idsToResolve));
  const notResolvedElements = filter((c) => !c.available, checkIds);
  if (notResolvedElements.length > 0) {
    throw MissingReferenceError({ input: map((n) => n.ref, notResolvedElements) });
  }
  // Generate the internal id
  const internalId = input.internal_id || generateInternalId();
  const standardId = generateStandardId(type, input);
  // Complete with identifiers
  const today = now();
  // Dissoc additional data
  let data = pipe(
    dissoc('createdBy'),
    dissoc('objectMarking'),
    dissoc('objectLabel'),
    dissoc('killChainPhases'),
    dissoc('externalReferences'),
    dissoc('object')
  )(input);
  // Default attributes
  // Basic-Object
  data = pipe(assoc('internal_id', internalId), assoc('entity_type', type))(data);
  // Internal-Object
  if (isInternalObject(type)) {
    data = assoc('standard_id', standardId, data);
  }
  // Some internal objects have dates
  if (isDatedInternalObject(type)) {
    data = pipe(assoc('created_at', today), assoc('updated_at', today))(data);
  }
  // Stix-Object
  if (isStixObject(type)) {
    data = pipe(
      assoc('standard_id', standardId),
      assoc('stix_ids', isNil(input.stix_id) ? [] : [input.stix_id]),
      dissoc('stix_id'),
      assoc('spec_version', STIX_SPEC_VERSION),
      assoc('created_at', today),
      assoc('updated_at', today)
    )(data);
  }
  // Stix-Meta-Object
  if (isStixMetaObject(type)) {
    data = pipe(
      assoc('created', isNil(input.created) ? today : input.created),
      assoc('modified', isNil(input.modified) ? today : input.modified)
    )(data);
  }
  // STIX-Core-Object
  // STIX-Domain-Object
  if (isStixDomainObject(type)) {
    data = pipe(
      assoc('revoked', isNil(data.revoked) ? false : data.revoked),
      assoc('confidence', isNil(data.confidence) ? 0 : data.confidence),
      assoc('lang', isNil(data.lang) ? 'en' : data.lang),
      assoc('created', isNil(input.created) ? today : input.created),
      assoc('modified', isNil(input.modified) ? today : input.modified)
    )(data);
  }
  // Add the additional fields for dates (day, month, year)
  const dataKeys = Object.keys(data);
  for (let index = 0; index < dataKeys.length; index += 1) {
    // Adding dates elements
    if (includes(dataKeys[index], statsDateAttributes)) {
      const dayValue = dayFormat(data[dataKeys[index]]);
      const monthValue = monthFormat(data[dataKeys[index]]);
      const yearValue = yearFormat(data[dataKeys[index]]);
      data = pipe(
        assoc(`${dataKeys[index]}_day`, dayValue),
        assoc(`${dataKeys[index]}_month`, monthValue),
        assoc(`${dataKeys[index]}_year`, yearValue)
      )(data);
    }
  }
  // Generate fields for query and build the query
  const queryElements = flatAttributesForObject(data);
  const nbElements = queryElements.length;
  let query = `insert $entity isa ${type}, `;
  for (let index = 0; index < nbElements; index += 1) {
    const { key, value } = queryElements[index];
    const insert = prepareAttribute(value);
    const separator = index + 1 === nbElements ? ';' : ',';
    if (!isNil(insert) && insert.length !== 0) {
      query += `has ${key} ${insert}${separator} `;
    }
  }
  let lock;
  try {
    // Try to get the lock in redis
    lock = await lockResource(internalId);
    // Create the input
    await executeWrite(async (wTx) => {
      logger.debug(`[GRAKN - infer: false] createEntity`, { query });
      await wTx.query(query);
    });
  } catch (err) {
    if (err.name === TYPE_DUPLICATE_ENTRY) {
      logger.warn(err.message, { input, ...err.data });
      return loadEntityById(err.data.id, type);
    }
    // Lock cant be acquired after 5 sec, assume input already exists.
    if (err.name === 'LockError') {
      logger.warn('Entity already exists (Redis)', { input, ...err.data });
      return loadEntityById(internalId, type);
    }
    throw err;
  } finally {
    if (lock) await lock.unlock();
  }
  // Transaction succeed, complete the result to send it back
  const completedData = pipe(
    assoc('id', internalId),
    assoc('base_type', BASE_TYPE_ENTITY),
    assoc('parent_types', getParentTypes(type))
  )(data);
  // Transaction succeed, index the result
  try {
    await elIndexElements([completedData]);
  } catch (err) {
    throw DatabaseError('Cannot index input', { error: err, data: completedData });
  }
  const postOperations = [];
  // Send creation log
  if (!noLog) postOperations.push(sendLog(EVENT_TYPE_CREATE, user, completedData));
  // Complete with eventual relations (will eventually update the index)
  if (isStixCoreObject(type)) {
    postOperations.push(
      addCreatedBy(user, internalId, input.createdBy, opts),
      addMarkingDefs(user, internalId, input.objectMarking, opts),
      addLabels(user, internalId, input.objectLabel, opts), // Embedded in same execution.
      addKillChains(user, internalId, input.killChainPhases, opts), // Embedded in same execution.
      addExternalReferences(user, internalId, input.externalReferences, opts),
      addObjects(user, internalId, input.object, opts)
    );
  }
  await Promise.all(postOperations);
  // Simply return the data
  return completedData;
};
// endregion

// region mutation update
const innerUpdateAttribute = async (user, instance, input, wTx, options = {}) => {
  const { id } = instance;
  const { noLog = false } = options;
  const { key, value } = input; // value can be multi valued
  // --- 01 Get the current attribute types
  const escapedKey = escape(key);
  const labelTypeQuery = `match $x type ${escapedKey}; get;`;
  const labelIterator = await wTx.query(labelTypeQuery);
  const labelAnswer = await labelIterator.next();
  // eslint-disable-next-line prettier/prettier
  const ansConcept = labelAnswer.map().get('x');
  const attrType = await ansConcept.asRemote(wTx).dataType();
  const typedValues = map((v) => {
    if (attrType === GraknString) return `"${escapeString(v)}"`;
    if (attrType === GraknDate) return prepareDate(v);
    return escape(v);
  }, value);
  // --- Delete the old attribute
  const entityId = `${escapeString(id)}`;
  const deleteQuery = `match $x has internal_id "${entityId}", has ${escapedKey} $del via $d; delete $d;`;
  logger.debug(`[GRAKN - infer: false] updateAttribute - delete`, { query: deleteQuery });
  await wTx.query(deleteQuery);
  if (typedValues.length > 0) {
    let graknValues;
    if (typedValues.length === 1) {
      graknValues = `has ${escapedKey} ${head(typedValues)}`;
    } else {
      graknValues = `${join(
        ' ',
        map((gVal) => `has ${escapedKey} ${gVal},`, tail(typedValues))
      )} has ${escapedKey} ${head(typedValues)}`;
    }
    const createQuery = `match $x has internal_id "${entityId}"; insert $x ${graknValues};`;
    logger.debug(`[GRAKN - infer: false] updateAttribute - insert`, { query: createQuery });
    await wTx.query(createQuery);
  }
  // Adding dates elements
  const updateOperations = [];
  const noLogOpts = assoc('noLog', true, options);
  if (includes(key, statsDateAttributes)) {
    const dayValue = dayFormat(head(value));
    const monthValue = monthFormat(head(value));
    const yearValue = yearFormat(head(value));
    const dayInput = { key: `${key}_day`, value: [dayValue] };
    updateOperations.push(innerUpdateAttribute(user, instance, dayInput, wTx, noLogOpts));
    const monthInput = { key: `${key}_month`, value: [monthValue] };
    updateOperations.push(innerUpdateAttribute(user, instance, monthInput, wTx, noLogOpts));
    const yearInput = { key: `${key}_year`, value: [yearValue] };
    updateOperations.push(innerUpdateAttribute(user, instance, yearInput, wTx, noLogOpts));
  }
  // Update modified / updated_at
  if (isStixDomainObject(instance.entity_type) && key !== 'modified' && key !== 'updated_at') {
    const today = now();
    const updatedAtInput = { key: 'updated_at', value: [today] };
    updateOperations.push(innerUpdateAttribute(user, instance, updatedAtInput, wTx, noLogOpts));
    const modifiedAtInput = { key: 'modified', value: [today] };
    updateOperations.push(innerUpdateAttribute(user, instance, modifiedAtInput, wTx, noLogOpts));
  }
  await Promise.all(updateOperations);
  // Update elasticsearch
  const esOperations = [];
  const val = includes(key, multipleAttributes) ? value : head(value);
  // eslint-disable-next-line no-nested-ternary
  const typedVal = val === 'true' ? true : val === 'false' ? false : val;
  const updateValueField = { [key]: typedVal };
  const currentIndex = inferIndexFromConceptType(instance.entity_type);
  esOperations.push(
    elUpdate(currentIndex, instance.internal_id, { doc: updateValueField }).catch(
      /* istanbul ignore next */ (err) =>
        logger.error(`[ELASTIC] An error occured during the update of the element ${id}`, { error: err })
    )
  );
  if (!noLog && escapedKey !== 'graph_data') {
    esOperations.push(
      sendLog(
        EVENT_TYPE_UPDATE,
        user,
        {
          id: instance.id,
          stix_ids: instance.stix_ids,
          entity_type: instance.entity_type,
          [escapedKey]: includes(input.key, multipleAttributes) ? input.value : head(input.value),
        },
        { key: escapedKey, value: input.value }
      )
    );
  }
  await Promise.all(esOperations);
  return id;
};

export const updateAttribute = async (user, id, type, input, wTx, options = {}) => {
  // TODO IF PART OF KEY CHANGE, CHANGE THE STIX_ID
  const { forceUpdate = false } = options;
  const { key, value } = input; // value can be multi valued
  const currentInstanceData = await loadEntityById(id, type);
  if (!currentInstanceData) {
    throw FunctionalError(`Cant find element to update`, { id, type });
  }
  const val = includes(key, multipleAttributes) ? value : head(value);
  // --- 00 Need update?
  if (!forceUpdate && equals(currentInstanceData[key], val)) {
    return id;
  }
  // --- take lock, ensure no one currently create or update this element
  let lock;
  let updatedId;
  try {
    // Try to get the lock in redis
    lock = await lockResource(currentInstanceData.stix_id || currentInstanceData.internal_id);
    // Update the attribute
    updatedId = await innerUpdateAttribute(user, currentInstanceData, input, wTx, options);
  } finally {
    if (lock) await lock.unlock();
  }
  return updatedId;
};
// endregion

const getElementsRelated = async (targetId, elements = [], options = {}) => {
  const eid = escapeString(targetId);
  const read = `match $from has internal_id "${eid}"; 
    $rel($from, $to) isa ${ABSTRACT_BASIC_RELATIONSHIP}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    get;`;
  const connectedRelations = await find(read, ['rel'], options);
  const connectedRelationsIds = map((r) => ({ id: r.rel.id, relDependency: true }), connectedRelations);
  elements.push(...connectedRelationsIds);
  await Promise.all(connectedRelationsIds.map(({ id }) => getElementsRelated(id, elements, options)));
  return elements;
};

const deleteElementById = async (elementId, isRelation, options = {}) => {
  // 00. Load everything we need to remove
  const dependencies = [{ id: elementId, relDependency: isRelation }];
  await getElementsRelated(elementId, dependencies, options);
  // 01. Delete dependencies.
  // Remove all dep in reverse order to handle correctly relations
  for (let i = dependencies.length - 1; i >= 0; i -= 1) {
    const { id, relDependency } = dependencies[i];
    // eslint-disable-next-line no-await-in-loop
    await executeWrite(async (wTx) => {
      const query = `match $x has internal_id "${id}"; delete $x;`;
      logger.debug(`[GRAKN - infer: false] delete element ${id}`, { query });
      await wTx.query(query, { infer: false });
    }).then(async () => {
      // If element is a relation, modify the impacted from and to.
      if (relDependency) {
        await elRemoveRelationConnection(id);
      }
      // Remove the element itself from the index
      await elDeleteInstanceIds([id]);
    });
  }
};

// region mutation deletion
export const deleteEntityById = async (user, entityId, type, options = {}) => {
  const { noLog = false } = options;
  if (isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError(`You need to specify a type when deleting an entity`);
  }
  // Check consistency
  const entity = await loadEntityById(entityId, type, options);
  if (entity === null) {
    throw DatabaseError(`Cant find entity to delete ${entityId}`);
  }
  // Delete entity and all dependencies
  await deleteElementById(entityId, false, options);
  // Send the log if everything fine
  if (!noLog) {
    await sendLog(EVENT_TYPE_DELETE, user, entity);
  }
  return entityId;
};
export const deleteRelationById = async (user, relationId, type, options = {}) => {
  const { noLog = false } = options;
  if (isNil(type)) {
    /* istanbul ignore next */
    throw FunctionalError(`You need to specify a type when deleting a relation`);
  }
  const relation = await loadRelationById(relationId, type, options);
  if (relation === null) throw DatabaseError(`Cant find relation to delete ${relationId}`);
  await deleteElementById(relationId, true, options);
  // Send the log if everything fine
  if (!noLog) {
    const from = await elLoadById(relation.fromId);
    const to = await elLoadById(relation.toId);
    if (isStixMetaRelationship(relation.entity_type)) {
      if (relation.entity_type === RELATION_CREATED_BY) {
        await sendLog(EVENT_TYPE_UPDATE, user, relation, { from, to });
      } else {
        await sendLog(EVENT_TYPE_UPDATE_REMOVE, user, relation, { from, to });
      }
    } else {
      await sendLog(EVENT_TYPE_DELETE, user, relation, { from, to });
    }
  }
  return relationId;
};
export const deleteRelationsByFromAndTo = async (user, fromId, toId, relationshipType, scopeType) => {
  /* istanbul ignore if */
  if (isNil(scopeType)) {
    throw FunctionalError(`You need to specify a scope type when deleting a relation with from and to`);
  }
  const fromThing = await internalLoadEntityById(fromId);
  const toThing = await internalLoadEntityById(toId);
  const read = `match $from has internal_id "${fromThing.internal_id}"; 
    $to has internal_id "${toThing.internal_id}"; 
    $rel($from, $to) isa ${relationshipType}, has internal_id $rel_id;
    $from has internal_id $rel_from_id;
    $to has internal_id $rel_to_id;
    get;`;
  const relationsToDelete = await find(read, ['rel']);
  const relationsIds = map((r) => r.rel.id, relationsToDelete);
  for (let i = 0; i < relationsIds.length; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await deleteRelationById(user, relationsIds[i], scopeType);
  }
};
export const deleteAttributeById = async (id) => {
  return executeWrite(async (wTx) => {
    const query = `match $x id ${escape(id)}; delete $x;`;
    logger.debug(`[GRAKN - infer: false] deleteAttributeById`, { query });
    await wTx.query(query, { infer: false });
    return id;
  });
};
// endregion

// region inferences
/**
 * Load any grakn relation with base64 id containing the query pattern.
 * @param id
 * @returns {Promise}
 */
export const getRelationInferredById = async (id) => {
  return executeRead(async (rTx) => {
    const decodedQuery = Buffer.from(id, 'base64').toString('ascii');
    const query = `match ${decodedQuery} get;`;
    logger.debug(`[GRAKN - infer: true] getRelationInferredById`, { query });
    const answerIterator = await rTx.query(query);
    const answerConceptMap = await answerIterator.next();
    const concepts = await getConcepts(
      rTx,
      [answerConceptMap],
      extractQueryVars(query), //
      [INFERRED_RELATION_KEY],
      { noCache: true }
    );
    const relation = head(concepts).rel;
    const explanation = await answerConceptMap.explanation();
    const explanationAnswers = explanation.getAnswers();
    const inferences = [];
    // eslint-disable-next-line no-restricted-syntax
    for (const explanationAnswer of explanationAnswers) {
      const explanationMap = explanationAnswer.map();
      const explanationKeys = Array.from(explanationMap.keys());
      const queryVars = map((v) => ({ alias: v }), explanationKeys);
      const explanationRelationKey = last(filter((n) => n.includes(INFERRED_RELATION_KEY), explanationKeys));
      // eslint-disable-next-line no-await-in-loop
      const explanationConcepts = await getConcepts(rTx, [explanationAnswer], queryVars, [explanationRelationKey]);
      inferences.push({ node: head(explanationConcepts)[explanationRelationKey] });
    }
    return pipe(assoc('inferences', { edges: inferences }))(relation);
  });
};
// endregion
