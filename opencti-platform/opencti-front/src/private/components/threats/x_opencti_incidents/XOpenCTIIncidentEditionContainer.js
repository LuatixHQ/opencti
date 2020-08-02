import React, { Component } from 'react';
import PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import AppBar from '@material-ui/core/AppBar';
import Tabs from '@material-ui/core/Tabs';
import Tab from '@material-ui/core/Tab';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import { Close } from '@material-ui/icons';
import inject18n from '../../../../components/i18n';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import XOpenCTIIncidentEditionOverview from './XOpenCTIIncidentEditionOverview';
import XOpenCTIIncidentEditionDetails from './XOpenCTIIncidentEditionDetails';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
  },
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    backgroundColor: theme.palette.navAlt.background,
    color: theme.palette.header.text,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
});

class XOpenCTIXOpenCTIIncidentEditionContainer extends Component {
  constructor(props) {
    super(props);
    this.state = { currentTab: 0 };
  }

  handleChangeTab(event, value) {
    this.setState({ currentTab: value });
  }

  render() {
    const {
      t, classes, handleClose, XOpenCTIIncident,
    } = this.props;
    const { editContext } = XOpenCTIIncident;
    return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose.bind(this)}
          >
            <Close fontSize="small" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update an XOpenCTIIncident')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <AppBar position="static" elevation={0} className={classes.appBar}>
            <Tabs
              value={this.state.currentTab}
              onChange={this.handleChangeTab.bind(this)}
            >
              <Tab label={t('Overview')} />
              <Tab label={t('Details')} />
            </Tabs>
          </AppBar>
          {this.state.currentTab === 0 && (
            <XOpenCTIIncidentEditionOverview
              XOpenCTIIncident={XOpenCTIIncident}
              context={editContext}
            />
          )}
          {this.state.currentTab === 1 && (
            <XOpenCTIIncidentEditionDetails
              XOpenCTIIncident={XOpenCTIIncident}
              context={editContext}
            />
          )}
        </div>
      </div>
    );
  }
}

XOpenCTIXOpenCTIIncidentEditionContainer.propTypes = {
  handleClose: PropTypes.func,
  classes: PropTypes.object,
  XOpenCTIIncident: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
};

const XOpenCTIIncidentEditionContainerFragment = createFragmentContainer(
  XOpenCTIXOpenCTIIncidentEditionContainer,
  {
    XOpenCTIIncident: graphql`
      fragment XOpenCTIIncidentEditionContainer_XOpenCTIIncident on XOpenCTIIncident {
        id
        ...XOpenCTIIncidentEditionOverview_XOpenCTIIncident
        ...XOpenCTIIncidentEditionDetails_XOpenCTIIncident
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles, { withTheme: true }),
)(XOpenCTIIncidentEditionContainerFragment);