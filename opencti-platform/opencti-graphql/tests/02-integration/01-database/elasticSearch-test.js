/* eslint-disable no-underscore-dangle */
import { assoc, find, head, map, propEq, uniq } from 'ramda';
import moment from 'moment';
import {
  elAggregationCount,
  elAggregationRelationsCount,
  elCount,
  elCreateIndexes,
  elDeleteElements,
  elDeleteIndexes,
  elHistogramCount,
  elIndex,
  elIndexElements,
  elIndexExists,
  elIsAlive,
  elLoadById,
  elPaginate,
  elRebuildRelation,
  elVersion,
  specialElasticCharsEscape,
} from '../../../src/database/elasticSearch';
import {
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_SIGHTING_RELATIONSHIPS,
  READ_INDEX_STIX_CORE_RELATIONSHIPS,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
  READ_INDEX_STIX_META_OBJECTS,
  READ_INDEX_STIX_META_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS,
  READ_INDEX_INTERNAL_RELATIONSHIPS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_RELATIONSHIPS_INDICES,
  READ_ENTITIES_INDICES,
} from '../../../src/database/utils';
import { utcDate } from '../../../src/utils/format';
import { ADMIN_USER } from '../../utils/testQuery';
import { BASE_TYPE_RELATION } from '../../../src/schema/general';

describe('Elasticsearch configuration test', () => {
  it('should configuration correct', () => {
    expect(elIsAlive()).resolves.toBeTruthy();
    expect(elVersion()).resolves.toContain('7.13');
    expect(elIndexExists(READ_INDEX_INTERNAL_OBJECTS)).toBeTruthy();
    expect(elIndexExists(READ_INDEX_STIX_SIGHTING_RELATIONSHIPS)).toBeTruthy();
    expect(elIndexExists(READ_INDEX_STIX_CORE_RELATIONSHIPS)).toBeTruthy();
    expect(elIndexExists(READ_INDEX_STIX_DOMAIN_OBJECTS)).toBeTruthy();
    expect(elIndexExists(READ_INDEX_STIX_META_OBJECTS)).toBeTruthy();
    expect(elIndexExists(READ_INDEX_STIX_META_RELATIONSHIPS)).toBeTruthy();
    expect(elIndexExists(READ_INDEX_STIX_CYBER_OBSERVABLE_RELATIONSHIPS)).toBeTruthy();
    expect(elIndexExists(READ_INDEX_INTERNAL_RELATIONSHIPS)).toBeTruthy();
    expect(elIndexExists(READ_INDEX_STIX_CYBER_OBSERVABLES)).toBeTruthy();
  });
  it('should manage index', async () => {
    // Create index
    const createdIndices = await elCreateIndexes(['test_index']);
    expect(createdIndices.length).toEqual(1);
    expect(head(createdIndices).body.acknowledged).toBeTruthy();
    expect(head(createdIndices).body.index).toEqual('test_index-000001');
    // Remove index
    const deletedIndices = await elDeleteIndexes(['test_index-000001']);
    expect(deletedIndices.length).toEqual(1);
    expect(head(deletedIndices).body.acknowledged).toBeTruthy();
  });
});

describe('Elasticsearch document loader', () => {
  beforeAll(async () => {
    await elCreateIndexes(['test_index']);
  });
  afterAll(async () => {
    await elDeleteIndexes(['test_index-000001']);
  });

  it('should create and retrieve document', async () => {
    // Index an element and try to retrieve the data
    const standardId = 'campaign--aae8b913-564b-405e-a9c1-5e5ea6c60259';
    const internalId = '867d03f4-be73-44f6-82d9-7d7b14df55d7';
    const documentBody = {
      internal_id: internalId,
      standard_id: standardId,
      name: 'Germany - Maze - October 2019',
      entity_type: 'Campaign',
      parent_types: ['Campaign', 'Stix-Domain-Object', 'Stix-Core-Object', 'Stix-Object', 'Basic-Object'],
    };
    const indexedData = await elIndex('test_index', documentBody);
    expect(indexedData).toEqual(documentBody);
    const documentWithIndex = assoc('_index', 'test_index-000001', documentBody);
    // Load by internal Id
    const dataThroughInternal = await elLoadById(ADMIN_USER, internalId, null, ['test_index']);
    expect(dataThroughInternal.standard_id).toEqual(documentWithIndex.standard_id);
    // Load by stix id
    const dataThroughStix = await elLoadById(ADMIN_USER, standardId, null, ['test_index']);
    expect(dataThroughStix.standard_id).toEqual(documentWithIndex.standard_id);
    // Try to delete
    await elDeleteElements(ADMIN_USER, [dataThroughStix]);
    const removedInternal = await elLoadById(ADMIN_USER, internalId, null, ['test_index']);
    expect(removedInternal).toBeUndefined();
  });
});

describe('Elasticsearch computation', () => {
  it('should count accurate', async () => {
    // const { endDate = null, type = null, types = null } = options;
    const malwaresCount = await elCount(ADMIN_USER, READ_ENTITIES_INDICES, { types: ['Malware'] });
    expect(malwaresCount).toEqual(2);
  });
  it('should count accurate with date filter', async () => {
    const mostRecentMalware = await elLoadById(ADMIN_USER, 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    const malwaresCount = await elCount(ADMIN_USER, READ_ENTITIES_INDICES, {
      types: ['Malware'],
      endDate: mostRecentMalware.created_at,
    });
    expect(malwaresCount).toEqual(1);
  });
  it('should entity aggregation accurate', async () => {
    // { "isRelation", "from", "to", "type", "value" }
    // "from", "to" is not use in elastic
    // Aggregate all stix domain by entity type, no filtering
    const malwaresAggregation = await elAggregationCount(
      ADMIN_USER,
      'Stix-Domain-Object',
      'entity_type',
      undefined,
      undefined,
      []
    );
    const aggregationMap = new Map(malwaresAggregation.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Malware')).toEqual(2);
    expect(aggregationMap.get('Indicator')).toEqual(3);
  });
  it('should entity aggregation with date accurate', async () => {
    const mostRecentMalware = await elLoadById(ADMIN_USER, 'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
    const malwaresAggregation = await elAggregationCount(
      ADMIN_USER,
      'Stix-Domain-Object',
      'entity_type',
      '2019-01-01T00:00:00Z',
      new Date(mostRecentMalware.created_at).getTime() - 1,
      [
        {
          type: 'name',
          value: 'Paradise Ransomware',
        },
      ]
    );
    const aggregationMap = new Map(malwaresAggregation.map((i) => [i.label, i.value]));
    expect(aggregationMap.size).toEqual(1);
    expect(aggregationMap.get('Malware')).toEqual(1);
  });
  it('should entity aggregation with relation accurate', async () => {
    // Aggregate with relation filter on marking definition TLP:RED
    const marking = await elLoadById(ADMIN_USER, 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27');
    const malwaresAggregation = await elAggregationCount(
      ADMIN_USER,
      'Stix-Domain-Object',
      'entity_type',
      undefined,
      undefined,
      [
        {
          isRelation: true,
          type: 'object-marking',
          value: marking.internal_id,
        },
      ]
    );
    const aggregationMap = new Map(malwaresAggregation.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Malware')).toEqual(1);
    expect(aggregationMap.get('Report')).toEqual(1);
  });
  it('should relation aggregation accurate', async () => {
    const testingReport = await elLoadById(ADMIN_USER, 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    const opts = {
      toTypes: ['Stix-Domain-Object'],
      fromId: testingReport.internal_id,
    };
    const reportRelationsAggregation = await elAggregationRelationsCount(ADMIN_USER, 'stix-meta-relationship', opts);
    const aggregationMap = new Map(reportRelationsAggregation.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('Indicator')).toEqual(3);
    expect(aggregationMap.get('Organization')).toEqual(3);
    expect(aggregationMap.get('Attack-Pattern')).toEqual(2);
    expect(aggregationMap.get('City')).toEqual(1);
    expect(aggregationMap.get('Country')).toEqual(1);
    expect(aggregationMap.get('Intrusion-Set')).toEqual(1);
    expect(aggregationMap.get('Malware')).toEqual(1);
    expect(aggregationMap.get('Sector')).toEqual(1);
  });

  /*
  export const elAggregationRelationsCount = async (
    user,
    type,
    start,
    end,
    toTypes,
    fromId = null,
    field = null,
    dateAttribute = 'created_at',
    isTo = false,
    noDirection = false
  ) => {
   */

  it('should relation aggregation with date accurate', async () => {
    // "target_ref": "location--c3794ffd-0e71-4670-aa4d-978b4cbdc72c", City -> Hietzing
    // "target_ref": "malware--faa5b705-cf44-4e50-8472-29e5fec43c3c"
    const intrusionSet = await elLoadById(ADMIN_USER, 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    // "target_ref": "identity--c017f212-546b-4f21-999d-97d3dc558f7b", organization -> Allied Universal
    const opts = {
      start: '2020-02-29T00:00:00Z',
      end: new Date().getTime(),
      toTypes: ['Stix-Domain-Object'],
      fromId: intrusionSet.internal_id,
      noDirection: true,
    };
    const intrusionRelationsAggregation = await elAggregationRelationsCount(ADMIN_USER, 'stix-core-relationship', opts);
    const aggregationMap = new Map(intrusionRelationsAggregation.map((i) => [i.label, i.value]));
    expect(aggregationMap.get('City')).toEqual(1);
    expect(aggregationMap.get('Indicator')).toEqual(1);
    expect(aggregationMap.get('Organization')).toEqual(1);
    expect(aggregationMap.get('Malware')).toEqual(1); // Because of date filtering
  });
  it('should invalid time histogram fail', async () => {
    const histogramCount = elHistogramCount(ADMIN_USER, 'Stix-Domain-Object', 'created_at', 'minute', null, null, []);
    // noinspection ES6MissingAwait.toEqual(36);
    expect(histogramCount).rejects.toThrow();
  });
  it('should day histogram accurate', async () => {
    const data = await elHistogramCount(
      ADMIN_USER,
      'Stix-Domain-Object',
      'created_at',
      'day',
      '2019-09-29T00:00:00.000Z',
      new Date().getTime(),
      [],
      []
    );
    expect(data.length).toEqual(1);
    // noinspection JSUnresolvedVariable
    const storedFormat = moment(head(data).date)._f;
    expect(storedFormat).toEqual('YYYY-MM-DD');
    expect(head(data).value).toEqual(28);
  });
  it('should month histogram accurate', async () => {
    const data = await elHistogramCount(
      ADMIN_USER,
      'Stix-Domain-Object',
      'created',
      'month',
      '2019-09-23T00:00:00.000Z',
      '2020-03-02T00:00:00.000Z',
      [],
      []
    );
    expect(data.length).toEqual(7);
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019-08')).toEqual(undefined);
    expect(aggregationMap.get('2019-09')).toEqual(2);
    expect(aggregationMap.get('2019-10')).toEqual(3);
    expect(aggregationMap.get('2019-11')).toEqual(0);
    expect(aggregationMap.get('2019-12')).toEqual(0);
    expect(aggregationMap.get('2020-01')).toEqual(1);
    expect(aggregationMap.get('2020-02')).toEqual(12);
    expect(aggregationMap.get('2020-03')).toEqual(1);
  });
  it('should year histogram accurate', async () => {
    const data = await elHistogramCount(
      ADMIN_USER,
      'Stix-Domain-Object',
      'created',
      'year',
      '2019-09-23T00:00:00.000Z',
      '2020-03-02T00:00:00.000Z',
      [],
      []
    );
    expect(data.length).toEqual(2);
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019')).toEqual(5);
    expect(aggregationMap.get('2020')).toEqual(14);
  });
  it('should year histogram with relation filter accurate', async () => {
    const attackPattern = await elLoadById(ADMIN_USER, 'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc');
    const data = await elHistogramCount(
      ADMIN_USER,
      'Stix-Domain-Object',
      'created',
      'year',
      '2019-09-23T00:00:00.000Z',
      '2020-03-02T00:00:00.000Z',
      [],
      [
        {
          isRelation: true,
          type: 'uses',
          value: attackPattern.internal_id,
        },
      ]
    );
    expect(data.length).toEqual(1);
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019')).toEqual(1);
  });
  it('should year histogram with relation filter accurate', async () => {
    const attackPattern = await elLoadById(ADMIN_USER, 'attack-pattern--489a7797-01c3-4706-8cd1-ec56a9db3adc');
    const data = await elHistogramCount(
      ADMIN_USER,
      'Stix-Domain-Object',
      'created',
      'year',
      '2019-09-23T00:00:00.000Z',
      '2020-03-02T00:00:00.000Z',
      [],
      [
        {
          isRelation: true,
          type: undefined,
          value: attackPattern.internal_id,
        },
      ]
    );
    expect(data.length).toEqual(2);
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2019')).toEqual(1);
    expect(aggregationMap.get('2020')).toEqual(1);
  });
  it('should year histogram with attribute filter accurate', async () => {
    const data = await elHistogramCount(
      ADMIN_USER,
      'Identity',
      'created',
      'year',
      undefined, // No start
      undefined, // No end
      [],
      [{ isRelation: false, type: 'name', value: 'ANSSI' }]
    );
    expect(data.length).toEqual(1);
    const aggregationMap = new Map(data.map((i) => [i.date, i.value]));
    expect(aggregationMap.get('2020')).toEqual(1);
  });
});

describe('Elasticsearch relation reconstruction', () => {
  const RELATION_ID = 'a0cfc7fc-837b-5ea0-b919-425047d4bb0d';
  const CONN_MALWARE_ID = '6fb84f02-f095-430e-87a0-394d41955eee';
  const CONN_MALWARE_ROLE = 'object-marking_from';
  const CONN_MARKING_ID = '63309927-48f6-45c2-aee0-4d92b403cee5';
  const CONN_MARKING_ROLE = 'object-marking_to';
  const buildRelationConcept = (relationshipType) => ({
    internal_id: RELATION_ID,
    base_type: BASE_TYPE_RELATION,
    entity_type: 'object-marking',
    relationship_type: relationshipType,
    connections: [
      {
        internal_id: CONN_MALWARE_ID,
        role: CONN_MALWARE_ROLE,
        types: ['Malware', 'Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
      },
      {
        internal_id: CONN_MARKING_ID,
        role: CONN_MARKING_ROLE,
        types: ['Marking-Definition', 'Basic-Object', 'Stix-Object', 'Stix-Meta-Object'],
      },
    ],
  });
  it('Relation reconstruct natural', async () => {
    const concept = buildRelationConcept('object-marking');
    const relation = elRebuildRelation(concept);
    expect(relation.fromId).toEqual(CONN_MALWARE_ID);
    expect(relation.fromRole).toEqual(CONN_MALWARE_ROLE);
    expect(relation.toId).toEqual(CONN_MARKING_ID);
    expect(relation.toRole).toEqual(CONN_MARKING_ROLE);
  });
  it('Relation reconstruct with internal_id', async () => {
    const concept = buildRelationConcept('object-marking');
    const relation = elRebuildRelation(concept);
    expect(relation.internal_id).toEqual(concept.internal_id);
    expect(relation.fromId).toEqual(CONN_MALWARE_ID);
    expect(relation.fromRole).toEqual(CONN_MALWARE_ROLE);
    expect(relation.toId).toEqual(CONN_MARKING_ID);
    expect(relation.toRole).toEqual(CONN_MARKING_ROLE);
  });
  it('Relation reconstruct with no info', async () => {
    const concept = buildRelationConcept('object-marking');
    const relation = elRebuildRelation(concept);
    expect(relation.fromId).toEqual(CONN_MALWARE_ID);
    expect(relation.toId).toEqual(CONN_MARKING_ID);
  });
  it('Relation reconstruct from reverse id', async () => {
    const concept = buildRelationConcept('object-marking');
    const relation = elRebuildRelation(concept);
    expect(relation.fromId).toEqual(CONN_MALWARE_ID);
    expect(relation.toId).toEqual(CONN_MARKING_ID);
  });
  it('Relation reconstruct from roles', async () => {
    const concept = buildRelationConcept('object-marking');
    const relation = elRebuildRelation(concept);
    expect(relation.fromId).toEqual(CONN_MALWARE_ID);
    expect(relation.toId).toEqual(CONN_MARKING_ID);
  });
});

describe('Elasticsearch pagination', () => {
  it('Pagination standard escape', async () => {
    // +|\-*()~={}:?\\
    let escape = specialElasticCharsEscape('Looking {for} [malware] : ~APT');
    expect(escape).toEqual('Looking \\{for\\} \\[malware\\] \\: \\~APT');
    escape = specialElasticCharsEscape('Looking (threat) = ?maybe');
    expect(escape).toEqual('Looking \\(threat\\) \\= \\?maybe');
    escape = specialElasticCharsEscape('Looking All* + Everything| - \\with');
    expect(escape).toEqual('Looking All\\* \\+ Everything\\| \\- \\\\with');
  });
  it('should entity paginate everything', async () => {
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES);
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(87);
    const filterBaseTypes = uniq(map((e) => e.node.base_type, data.edges));
    expect(filterBaseTypes.length).toEqual(1);
    expect(head(filterBaseTypes)).toEqual('ENTITY');
  });
  it('should entity search with trailing slash', async () => {
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: 'groups/G0096' });
    expect(data).not.toBeNull();
    // external-reference--d1b50d16-2c9c-45f2-8ae0-d5b554e0fbf5 | url
    // intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7 | description
    expect(data.edges.length).toEqual(2);
  });
  it('should entity paginate everything after', async () => {
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, {
      after: 'WyJleHRlcm5hbC1yZWZlcmVuY2UtLTUzYjNhZGI2LWQ4M2YtNWQyMS05Mzc2LTQ1YTE5OGU0NDA3ZSJd',
    });
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(55);
  });
  it('should entity paginate with single type', async () => {
    // first = 200, after, types = null, filters = [], search = null,
    // orderBy = null, orderMode = 'asc',
    // connectionFormat = true
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { types: ['Malware'] });
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(2);
    const nodes = map((e) => e.node, data.edges);
    const malware = find(propEq('x_opencti_stix_ids', ['malware--faa5b705-cf44-4e50-8472-29e5fec43c3c']))(nodes);
    expect(malware.internal_id).not.toBeNull();
    expect(malware.name).toEqual('Paradise Ransomware');
    expect(malware._index).not.toBeNull();
    expect(malware.parent_types).toEqual(
      expect.arrayContaining(['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'])
    );
  });
  it('should entity paginate with classic search', async () => {
    let data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: 'malicious' });
    expect(data.edges.length).toEqual(3);
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: 'with malicious' });
    expect(data.edges.length).toEqual(5);
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: '"with malicious"' });
    expect(data.edges.length).toEqual(2);
  });
  it('should entity paginate with escaped search', async () => {
    let data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: '(Citation:' });
    expect(data.edges.length).toEqual(3);
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: '[APT41]' });
    expect(data.edges.length).toEqual(1);
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: '%5BAPT41%5D' });
    expect(data.edges.length).toEqual(1);
  });
  it('should entity paginate with http and https', async () => {
    let data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: 'http://attack.mitre.org/groups/G0096' });
    expect(data.edges.length).toEqual(2);
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: 'https://attack.mitre.org/groups/G0096' });
    expect(data.edges.length).toEqual(2);
  });
  it('should entity paginate with incorrect encoding', async () => {
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { search: 'ATT%' });
    expect(data.edges.length).toEqual(0);
  });
  it('should entity paginate with field not exist filter', async () => {
    const filters = [{ key: 'x_opencti_color', operator: undefined, values: [null] }];
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(81); // The 4 Default TLP Marking definitions + 1
  });
  it('should entity paginate with field exist filter', async () => {
    const filters = [{ key: 'x_opencti_color', operator: undefined, values: ['EXISTS'] }];
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(6); // The 4 Default TLP Marking definitions
  });
  it('should entity paginate with equality filter', async () => {
    // eq operation will use the field.keyword to do an exact field equality
    let filters = [{ key: 'x_opencti_color', operator: 'eq', values: ['#c62828'] }];
    let data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(1);
    // Special case when operator = eq + the field key is a dateFields => use a match
    filters = [{ key: 'published', operator: 'eq', values: ['2020-03-01'] }];
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(1);
  });
  it('should entity paginate with match filter', async () => {
    let filters = [{ key: 'entity_type', operator: 'match', values: ['marking'] }];
    let data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(6); // The 4 Default TLP + MITRE Corporation
    // Verify that nothing is found in this case if using the eq operator
    filters = [{ key: 'entity_type', operator: 'eq', values: ['marking'] }];
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(0);
  });
  it('should entity paginate with dates filter', async () => {
    let filters = [{ key: 'created', operator: 'lte', values: ['2017-06-01T00:00:00.000Z'] }];
    let data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(2); // The 4 Default TLP + MITRE Corporation
    filters = [
      { key: 'created', operator: 'gt', values: ['2020-03-01T14:06:06.255Z'] },
      { key: 'color', operator: undefined, values: [null] },
    ];
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(18);
    filters = [
      { key: 'created', operator: 'lte', values: ['2017-06-01T00:00:00.000Z'] },
      { key: 'created', operator: 'gt', values: ['2020-03-01T14:06:06.255Z'] },
    ];
    data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { filters });
    expect(data.edges.length).toEqual(0);
  });
  it('should entity paginate with date ordering', async () => {
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, { orderBy: 'created', orderMode: 'asc' });
    expect(data.edges.length).toEqual(56);
    const createdDates = map((e) => e.node.created, data.edges);
    let previousCreatedDate = null;
    for (let index = 0; index < createdDates.length; index += 1) {
      const createdDate = createdDates[index];
      if (!previousCreatedDate) {
        previousCreatedDate = createdDate;
      } else {
        const previousMoment = utcDate(previousCreatedDate);
        const currentMoment = utcDate(createdDate);
        expect(previousMoment.isValid()).toBeTruthy();
        expect(currentMoment.isValid()).toBeTruthy();
        expect(previousMoment.isSameOrBefore(currentMoment)).toBeTruthy();
      }
    }
  });
  it('should entity paginate with keyword ordering', async () => {
    const filters = [{ key: 'x_opencti_color', operator: undefined, values: ['EXISTS'] }];
    const data = await elPaginate(ADMIN_USER, READ_ENTITIES_INDICES, {
      filters,
      orderBy: 'definition',
      orderMode: 'desc',
    });
    expect(data.edges.length).toEqual(6);
    const markings = map((e) => e.node.definition, data.edges);
    expect(markings[0]).toEqual('TLP:WHITE');
    expect(markings[1]).toEqual('TLP:TEST');
    expect(markings[2]).toEqual('TLP:RED');
    expect(markings[3]).toEqual('TLP:GREEN');
    expect(markings[4]).toEqual('TLP:AMBER');
  });
  it('should relation paginate everything', async () => {
    let data = await elPaginate(ADMIN_USER, READ_RELATIONSHIPS_INDICES);
    expect(data).not.toBeNull();
    expect(data.edges.length).toEqual(146);
    let filterBaseTypes = uniq(map((e) => e.node.base_type, data.edges));
    expect(filterBaseTypes.length).toEqual(1);
    expect(head(filterBaseTypes)).toEqual('RELATION');
    // Same query with no pagination
    data = await elPaginate(ADMIN_USER, READ_RELATIONSHIPS_INDICES, { connectionFormat: false });
    expect(data).not.toBeNull();
    expect(data.length).toEqual(146);
    filterBaseTypes = uniq(map((e) => e.base_type, data));
    expect(filterBaseTypes.length).toEqual(1);
    expect(head(filterBaseTypes)).toEqual('RELATION');
  });
});

describe('Elasticsearch basic loader', () => {
  it('should entity load by internal id', async () => {
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c', 'Stix-Domain-Object');
    const data = await elLoadById(ADMIN_USER, malware.internal_id);
    expect(data).not.toBeNull();
    expect(data.standard_id).toEqual('malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714');
    expect(data.revoked).toBeFalsy();
    expect(data.name).toEqual('Paradise Ransomware');
    expect(data.entity_type).toEqual('Malware');
  });
  it('should entity load by stix id', async () => {
    const data = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c', 'Stix-Domain-Object');
    expect(data).not.toBeNull();
    expect(data.revoked).toBeFalsy();
    expect(data.name).toEqual('Paradise Ransomware');
    expect(data.entity_type).toEqual('Malware');
  });
  it('should relation reconstruct', async () => {
    const data = await elLoadById(ADMIN_USER, 'relationship--8d2200a8-f9ef-4345-95d1-ba3ed49606f9');
    expect(data).not.toBeNull();
    expect(data.fromRole).toEqual('indicates_from');
    expect(data.toRole).toEqual('indicates_to');
    expect(data.entity_type).toEqual('indicates');
  });
});

describe('Elasticsearch reindex', () => {
  it('should relation correctly indexed', async () => {
    const malware = await elLoadById(ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    const malwareInternalId = malware.internal_id;
    const attackPattern = await elLoadById(ADMIN_USER, 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17');
    const attackPatternId = attackPattern.internal_id;
    // relationship_type -> uses
    // source_ref -> malware--faa5b705-cf44-4e50-8472-29e5fec43c3c
    // target_ref -> attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17
    const data = await elLoadById(ADMIN_USER, 'relationship--1fc9b5f8-3822-44c5-85d9-ee3476ca26de');
    expect(data).not.toBeNull();
    expect(data.fromId === malwareInternalId).toBeTruthy(); // malware--faa5b705-cf44-4e50-8472-29e5fec43c3c
    expect(data.toId === attackPatternId).toBeTruthy(); // attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17
  });
  it('should relation reindex check consistency', async () => {
    const indexPromise = elIndexElements([{ relationship_type: 'uses' }]);
    // noinspection ES6MissingAwait
    expect(indexPromise).rejects.toThrow();
  });
});
