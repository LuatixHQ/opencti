import { head } from 'ramda';
import { elPaginate, INDEX_LOGS } from '../database/elasticSearch';
import conf from '../config/conf';
import { amqpUri, EVENT_TYPE_CREATE } from '../database/rabbitmq';
import { findById, OPENCTI_ADMIN_UUID, SYSTEM_USER } from './user';

export const findAll = (args) => elPaginate(INDEX_LOGS, args);

export const creator = async (entityId) =>
  elPaginate(INDEX_LOGS, {
    filters: [
      { key: 'event_type', values: [EVENT_TYPE_CREATE] },
      { key: 'event_data.x_opencti_id', values: [entityId] },
    ],
    connectionFormat: false,
  }).then((logs) =>
    logs.length > 0 && head(logs).event_user
      ? findById(head(logs).event_user)
      : { id: OPENCTI_ADMIN_UUID, name: SYSTEM_USER.name }
  );

export const logsWorkerConfig = () => ({
  elasticsearch_url: conf.get('elasticsearch:url'),
  elasticsearch_index: INDEX_LOGS,
  rabbitmq_url: amqpUri(),
});
