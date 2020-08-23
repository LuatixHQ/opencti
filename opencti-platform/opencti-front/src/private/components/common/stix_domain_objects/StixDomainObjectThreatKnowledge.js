import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import CircularProgress from '@material-ui/core/CircularProgress';
import Card from '@material-ui/core/Card';
import CardContent from '@material-ui/core/CardContent';
import Grid from '@material-ui/core/Grid';
import { withStyles } from '@material-ui/core/styles';
import { ShieldSearch } from 'mdi-material-ui';
import { AssignmentOutlined, DeviceHubOutlined } from '@material-ui/icons';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import Drawer from '@material-ui/core/Drawer';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import { resolveLink } from '../../../../utils/Entity';
import EntityReportsPie from '../../analysis/reports/EntityReportsPie';
import EntityStixCoreRelationshipsRadar from '../stix_core_relationships/EntityStixCoreRelationshipsRadar';
import StixDomainObjectGlobalKillChain, {
  stixDomainObjectGlobalKillChainStixCoreRelationshipsQuery,
} from './StixDomainObjectGlobalKillChain';
import Loader from '../../../../components/Loader';
import SimpleEntityStixCoreRelationships from '../stix_core_relationships/SimpleEntityStixCoreRelationships';

const styles = (theme) => ({
  card: {
    width: '100%',
    marginBottom: 20,
    borderRadius: 6,
    position: 'relative',
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  itemIconSecondary: {
    marginRight: 0,
    color: theme.palette.secondary.main,
  },
  number: {
    float: 'left',
    color: theme.palette.primary.main,
    fontSize: 40,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
  },
  icon: {
    position: 'absolute',
    top: 30,
    right: 20,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '5px 0 70px 0',
    padding: '15px 15px 15px 15px',
    borderRadius: 6,
  },
});

const stixDomainObjectThreatKnowledgeReportsNumberQuery = graphql`
  query StixDomainObjectThreatKnowledgeReportsNumberQuery(
    $objectId: String
    $endDate: DateTime
  ) {
    reportsNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery = graphql`
  query StixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery(
    $type: String
    $fromId: String
    $endDate: DateTime
    $inferred: Boolean
  ) {
    stixCoreRelationshipsNumber(
      type: $type
      fromId: $fromId
      endDate: $endDate
      inferred: $inferred
    ) {
      total
      count
    }
  }
`;

class StixDomainObjectThreatKnowledge extends Component {
  constructor(props) {
    super(props);
    this.state = {
      inferred: false,
    };
  }

  handleChangeInferred() {
    this.setState({
      inferred: !this.state.inferred,
    });
  }

  render() {
    const { inferred } = this.state;
    const {
      t, classes, stixDomainObjectId, stixDomainObjectType,
    } = this.props;
    const link = `${resolveLink(
      stixDomainObjectType,
    )}/${stixDomainObjectId}/knowledge`;
    const toTypes = ['Attack-Pattern', 'Malware', 'Tool', 'Vulnerability'];
    const killChainPaginationOptions = {
      fromId: stixDomainObjectId,
      toTypes: filter((n) => n.toLowerCase() !== stixDomainObjectType, toTypes),
      relationship_type: 'stix-core-relationship',
      inferred,
    };
    return (
      <div>
        <Drawer
          anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}
        >
          <Grid container={true} spacing={1}>
            <Grid item={true} xs="auto">
              <FormControlLabel
                style={{ paddingTop: 5, marginRight: 15 }}
                control={
                  <Switch
                    checked={inferred}
                    onChange={this.handleChangeInferred.bind(this)}
                    color="primary"
                  />
                }
                label={t('Inferences')}
              />
            </Grid>
          </Grid>
        </Drawer>
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4}>
            <Card
              raised={true}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={stixDomainObjectThreatKnowledgeReportsNumberQuery}
                variables={{
                  objectId: stixDomainObjectId,
                  endDate: monthsAgo(1),
                }}
                render={({ props }) => {
                  if (props && props.reportsNumber) {
                    const { total } = props.reportsNumber;
                    const difference = total - props.reportsNumber.count;
                    return (
                      <CardContent>
                        <div className={classes.number}>{total}</div>
                        <ItemNumberDifference
                          difference={difference}
                          description="last month"
                        />
                        <div className="clearfix" />
                        <div className={classes.title}>
                          {t('Total reports')}
                        </div>
                        <div className={classes.icon}>
                          <AssignmentOutlined
                            color="inherit"
                            fontSize="large"
                          />
                        </div>
                      </CardContent>
                    );
                  }
                  return (
                    <div style={{ textAlign: 'center', paddingTop: 35 }}>
                      <CircularProgress size={40} thickness={2} />
                    </div>
                  );
                }}
              />
            </Card>
          </Grid>
          <Grid item={true} xs={4}>
            <Card
              raised={true}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={
                  stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  fromId: stixDomainObjectId,
                  type: 'indicates',
                  endDate: monthsAgo(1),
                  inferred,
                }}
                render={({ props }) => {
                  if (props && props.stixCoreRelationshipsNumber) {
                    const { total } = props.stixCoreRelationshipsNumber;
                    const difference = total - props.stixCoreRelationshipsNumber.count;
                    return (
                      <CardContent>
                        <div className={classes.number}>{total}</div>
                        <ItemNumberDifference
                          difference={difference}
                          description="last month"
                        />
                        <div className="clearfix" />
                        <div className={classes.title}>
                          {t('Total indicators')}
                        </div>
                        <div className={classes.icon}>
                          <ShieldSearch color="inherit" fontSize="large" />
                        </div>
                      </CardContent>
                    );
                  }
                  return (
                    <div style={{ textAlign: 'center', paddingTop: 35 }}>
                      <CircularProgress size={40} thickness={2} />
                    </div>
                  );
                }}
              />
            </Card>
          </Grid>
          <Grid item={true} xs={4}>
            <Card
              raised={true}
              classes={{ root: classes.card }}
              style={{ height: 120 }}
            >
              <QueryRenderer
                query={
                  stixDomainObjectThreatKnowledgeStixCoreRelationshipsNumberQuery
                }
                variables={{
                  fromId: stixDomainObjectId,
                  endDate: monthsAgo(1),
                  inferred: false,
                }}
                render={({ props }) => {
                  if (props && props.stixCoreRelationshipsNumber) {
                    const { total } = props.stixCoreRelationshipsNumber;
                    const difference = total - props.stixCoreRelationshipsNumber.count;
                    return (
                      <CardContent>
                        <div className={classes.number}>{total}</div>
                        <ItemNumberDifference
                          difference={difference}
                          description="last month"
                        />
                        <div className="clearfix" />
                        <div className={classes.title}>
                          {t('Total relations')}
                        </div>
                        <div className={classes.icon}>
                          <DeviceHubOutlined color="inherit" fontSize="large" />
                        </div>
                      </CardContent>
                    );
                  }
                  return (
                    <div style={{ textAlign: 'center', paddingTop: 35 }}>
                      <CircularProgress size={40} thickness={2} />
                    </div>
                  );
                }}
              />
            </Card>
          </Grid>
        </Grid>
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={4} style={{ marginBottom: 50 }}>
            <EntityReportsPie
              entityId={stixDomainObjectId}
              field="created-by.name"
            />
          </Grid>
          <Grid item={true} xs={4} style={{ marginBottom: 50 }}>
            <EntityStixCoreRelationshipsRadar
              entityId={stixDomainObjectId}
              entityType="Stix-Domain-Object"
              relationshipType="stix-core-relationship"
              title={t('Distribution of relations')}
              field="entity_type"
              inferred={inferred}
            />
          </Grid>
          <Grid item={true} xs={4} style={{ marginBottom: 50 }}>
            <SimpleEntityStixCoreRelationships
              entityId={stixDomainObjectId}
              relationshipType="related-to"
              targetStixDomainObjectTypes={['Stix-Domain-Object']}
              entityLink={link}
            />
          </Grid>
        </Grid>
        <Typography variant="h4" gutterBottom={true}>
          {t('Global kill chain')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={stixDomainObjectGlobalKillChainStixCoreRelationshipsQuery}
            variables={{ first: 500, ...killChainPaginationOptions }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixDomainObjectGlobalKillChain
                    data={props}
                    entityLink={link}
                    paginationOptions={killChainPaginationOptions}
                    stixDomainObjectId={stixDomainObjectId}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Paper>
      </div>
    );
  }
}

StixDomainObjectThreatKnowledge.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectType: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectThreatKnowledge);
