import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import IndicatorHeader from './IndicatorHeader';
import IndicatorOverview from './IndicatorOverview';
import IndicatorDetails from './IndicatorDetails';
import IndicatorEdition from './IndicatorEdition';
import EntityLastReports from '../../analysis/reports/EntityLastReports';
import IndicatorEntities from './IndicatorEntities';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../analysis/notes/StixCoreObjectNotes';
import EntityExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 40,
  },
});

class IndicatorComponent extends Component {
  render() {
    const { classes, indicator } = this.props;
    return (
      <div className={classes.container}>
        <IndicatorHeader indicator={indicator} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={2}>
            <IndicatorOverview indicator={indicator} />
          </Grid>
          <Grid item={true} xs={5}>
            <IndicatorDetails indicator={indicator} />
          </Grid>
          <Grid item={true} xs={5}>
            <EntityLastReports entityId={indicator.id} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={7}>
            <IndicatorEntities
              entityId={indicator.id}
              relationshipType="indicates"
            />
          </Grid>
          <Grid item={true} xs={5}>
            <EntityExternalReferences entityId={indicator.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes entityId={indicator.id} marginTop={25} />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <IndicatorEdition indicatorId={indicator.id} />
        </Security>
      </div>
    );
  }
}

IndicatorComponent.propTypes = {
  indicator: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Indicator = createFragmentContainer(IndicatorComponent, {
  indicator: graphql`
    fragment Indicator_indicator on Indicator {
      id
      ...IndicatorHeader_indicator
      ...IndicatorOverview_indicator
      ...IndicatorDetails_indicator
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Indicator);
