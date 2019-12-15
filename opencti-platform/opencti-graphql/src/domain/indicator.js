import moment from 'moment';
import { assoc, dissoc, pipe, sortWith, descend, prop, head, map, includes } from 'ramda';
import {
  createEntity,
  escapeString,
  findWithConnectedRelations,
  listEntities,
  loadEntityById,
  loadEntityByStixId,
  TYPE_STIX_DOMAIN_ENTITY
} from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { notify } from '../database/redis';
import { buildPagination } from '../database/utils';
import { findById as findMarkingDefinitionById } from './markingDefinition';
import { findById as findKillChainPhaseById } from './killChainPhase';

const OpenCTITimeToLive = {
  file: {
    'TLP:WHITE-no': 365,
    'TLP:WHITE-yes': 365,
    'TLP:GREEN-no': 365,
    'TLP:GREEN-yes': 365,
    'TLP:AMBER-yes': 365,
    'TLP:AMBER-no': 365,
    'TLP:RED-yes': 365,
    'TLP:RED-no': 365
  },
  default: {
    'TLP:WHITE-no': 30,
    'TLP:WHITE-yes': 7,
    'TLP:GREEN-no': 30,
    'TLP:GREEN-yes': 7,
    'TLP:AMBER-yes': 15,
    'TLP:AMBER-no': 60,
    'TLP:RED-yes': 120,
    'TLP:RED-no': 120
  }
};

export const computeValidUntil = async indicator => {
  let validFrom = moment().utc();
  if (indicator.valid_from) {
    validFrom = moment(indicator.valid_from).utc();
  }
  // get the highest marking definition
  let markingDefinition = 'TLP:WHITE';
  if (indicator.markingDefinitions && indicator.markingDefinitions.length > 0) {
    const markingDefinitions = await Promise.all(
      indicator.markingDefinitions.map(markingDefinitionId => {
        return findMarkingDefinitionById(markingDefinitionId);
      })
    );
    markingDefinition = pipe(
      sortWith([descend(prop('level'))]),
      head,
      prop('definition')
    )(markingDefinitions);
  }
  // check if kill chain phase is delivery
  let isKillChainPhaseDelivery = 'no';
  if (indicator.killChainPhases && indicator.killChainPhases.length > 0) {
    const killChainPhases = await Promise.all(
      indicator.killChainPhases.map(killChainPhaseId => {
        return findKillChainPhaseById(killChainPhaseId);
      })
    );
    const killChainPhasesNames = map(n => n.phase_name, killChainPhases);
    isKillChainPhaseDelivery =
      includes('initial-access', killChainPhasesNames) || includes('execution', killChainPhasesNames) ? 'yes' : 'no';
  }
  // compute with delivery and marking definition
  const ttlPattern = `${markingDefinition}-${isKillChainPhaseDelivery}`;
  let ttl = OpenCTITimeToLive.default[ttlPattern];
  if (indicator.main_observable_type && includes(indicator.main_observable_type, OpenCTITimeToLive)) {
    ttl = OpenCTITimeToLive[indicator.main_observable_type][ttlPattern];
  }
  const validUntil = validFrom.add(ttl, 'days');
  return validUntil.toDate();
};

export const findById = indicatorId => {
  if (indicatorId.match(/[a-z-]+--[\w-]{36}/g)) {
    return loadEntityByStixId(indicatorId);
  }
  return loadEntityById(indicatorId);
};
export const findAll = args => {
  const typedArgs = assoc('types', ['Indicator'], args);
  return listEntities(['name', 'alias'], typedArgs);
};

export const addIndicator = async (user, indicator, createObservables = true) => {
  const indicatorToCreate = pipe(
    dissoc('main_observable_type'),
    assoc('score', indicator.score ? indicator.score : 50),
    assoc('valid_from', indicator.valid_from ? indicator.valid_from : Date.now()),
    assoc('valid_until', indicator.valid_until ? indicator.valid_until : await computeValidUntil(indicator))
  )(indicator);
  const created = await createEntity(indicatorToCreate, 'Indicator', TYPE_STIX_DOMAIN_ENTITY);
  return notify(BUS_TOPICS.StixDomainEntity.ADDED_TOPIC, created, user);
};

export const observableRefs = indicatorId => {
  return findWithConnectedRelations(
    `match $from isa Indicator; $rel(observables_aggregation:$from, soo:$to) isa observable_refs;
    $to isa Stix-Observable;
    $from has internal_id_key "${escapeString(indicatorId)}"; get;`,
    'to',
    'rel'
  ).then(data => buildPagination(0, 0, data, data.length));
};
