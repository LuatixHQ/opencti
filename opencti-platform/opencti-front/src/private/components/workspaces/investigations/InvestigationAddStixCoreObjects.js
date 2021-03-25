import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, includes } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import Avatar from '@material-ui/core/Avatar';
import { Add, Close } from '@material-ui/icons';
import Chip from '@material-ui/core/Chip';
import Alert from '@material-ui/lab/Alert';
import Tooltip from '@material-ui/core/Tooltip';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import InvestigationAddStixCoreObjectsLines, {
  investigationAddStixCoreObjectsLinesQuery,
} from './InvestigationAddStixCoreObjectsLines';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    backgroundColor: theme.palette.navAlt.background,
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 1100,
  },
  createButtonWithPadding: {
    position: 'fixed',
    bottom: 30,
    right: 280,
    zIndex: 1100,
  },
  createButtonSimple: {
    float: 'left',
    marginTop: -15,
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
  },
  investigation: {
    padding: 0,
    height: '100%',
    width: '100%',
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  avatar: {
    width: 24,
    height: 24,
  },
  speedDial: {
    position: 'fixed',
    bottom: 30,
    right: 30,
    zIndex: 2000,
  },
  info: {
    paddingTop: 10,
  },
});

class InvestigationAddStixCoreObjects extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSearch(keyword) {
    this.setState({ search: keyword });
  }

  static isTypeDomainObject(types) {
    return !types || includes('Stix-Domain-Object', types);
  }

  static isTypeObservable(types) {
    return !types || includes('Stix-Cyber-Observable', types);
  }

  renderSearchResults(paginationOptions) {
    const {
      classes, workspaceId, workspaceStixCoreObjects, t,
    } = this.props;
    const { search } = this.state;

    return (
      <div>
        {search.length === 0 && (
          <Alert
            severity="info"
            variant="outlined"
            style={{ margin: '15px 15px 0 15px' }}
            classes={{ message: classes.info }}
          >
            {t(
              'This panel shows by default the latest created entities, use the search to find more.',
            )}
          </Alert>
        )}
        <QueryRenderer
          query={investigationAddStixCoreObjectsLinesQuery}
          variables={{ count: 100, ...paginationOptions }}
          render={({ props }) => {
            if (props) {
              return (
                <InvestigationAddStixCoreObjectsLines
                  workspaceId={workspaceId}
                  data={props}
                  paginationOptions={this.props.paginationOptions}
                  workspaceStixCoreObjects={workspaceStixCoreObjects}
                  onAdd={this.props.onAdd}
                  onDelete={this.props.onDelete}
                />
              );
            }
            return (
              <List>
                {Array.from(Array(20), (e, i) => (
                  <ListItem key={i} divider={true} button={false}>
                    <ListItemIcon>
                      <Avatar classes={{ root: classes.avatar }}>{i}</Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <span className="fakeItem" style={{ width: '80%' }} />
                      }
                      secondary={
                        <span className="fakeItem" style={{ width: '90%' }} />
                      }
                    />
                  </ListItem>
                ))}
              </List>
            );
          }}
        />
      </div>
    );
  }

  renderSearch(paginationOptions) {
    return this.renderSearchResults(paginationOptions);
  }

  getSearchTypes() {
    const { paginationOptions, targetStixCoreObjectTypes } = this.props;
    let searchTypes;
    if (targetStixCoreObjectTypes !== undefined) {
      searchTypes = [...targetStixCoreObjectTypes];
    }
    if (paginationOptions !== undefined) {
      const { types } = paginationOptions;
      searchTypes = [...types];
    }
    return searchTypes;
  }

  getPaginationOptions() {
    const { targetStixCoreObjectTypes } = this.props;
    const { search } = this.state;
    let orderMode = 'desc';
    let orderBy = 'created_at';
    if (
      targetStixCoreObjectTypes
      && InvestigationAddStixCoreObjects.isTypeObservable(
        targetStixCoreObjectTypes,
      )
    ) {
      orderBy = 'created_at';
    }
    if (search.length > 0) {
      orderBy = null;
      orderMode = null;
    }
    const types = this.getSearchTypes();
    return {
      types,
      search,
      orderBy,
      orderMode,
    };
  }

  onSearchTypeFilterDelete(typeFilter) {
    this.props.onTypesChange(typeFilter);
  }

  renderSearchTypeFilter(paginationOptions) {
    if (!paginationOptions) {
      return null;
    }
    const { types } = paginationOptions;
    if (!types) {
      return null;
    }
    if (
      types.length === 1
      && (InvestigationAddStixCoreObjects.isTypeDomainObject(types)
        || InvestigationAddStixCoreObjects.isTypeObservable(types))
    ) {
      return null;
    }
    const { t } = this.props;
    const renderedTypes = types.map((type) => (
      <Chip
        key={type}
        color="secondary"
        style={{ marginLeft: '10px' }}
        label={t(`entity_${type}`)}
        onDelete={
          typeof this.props.onTypesChange === 'function'
            ? this.onSearchTypeFilterDelete.bind(this, type)
            : null
        }
      />
    ));

    return (
      <div style={{ float: 'left', margin: '-3px 0 0 5px' }}>
        {renderedTypes}
      </div>
    );
  }

  render() {
    const { t, classes } = this.props;
    const paginationOptions = this.getPaginationOptions();
    return (
      <div>
        <Tooltip title={t('Add an entity to this investigation')}>
          <IconButton
            color="primary"
            aria-label="Add"
            onClick={this.handleOpen.bind(this)}
          >
            <Add />
          </IconButton>
        </Tooltip>
        <Drawer
          open={this.state.open}
          keepMounted={true}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleClose.bind(this)}
        >
          <div className={classes.header}>
            <IconButton
              aria-label="Close"
              className={classes.closeButton}
              onClick={this.handleClose.bind(this)}
            >
              <Close fontSize="small" />
            </IconButton>
            {(InvestigationAddStixCoreObjects.isTypeDomainObject(
              paginationOptions.types,
            )
              || InvestigationAddStixCoreObjects.isTypeObservable(
                paginationOptions.types,
              )) && (
              <Typography variant="h6" classes={{ root: classes.title }}>
                {t('Add entities')}
              </Typography>
            )}
            {this.renderSearchTypeFilter(paginationOptions)}
            <div className={classes.search}>
              <SearchInput
                variant="inDrawer"
                placeholder={`${t('Search')}...`}
                onSubmit={this.handleSearch.bind(this)}
              />
            </div>
          </div>
          <div className={classes.investigation}>
            {this.renderSearch(paginationOptions)}
          </div>
        </Drawer>
      </div>
    );
  }
}

InvestigationAddStixCoreObjects.propTypes = {
  workspaceId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  withPadding: PropTypes.bool,
  defaultCreatedBy: PropTypes.object,
  defaultMarkingDefinitions: PropTypes.array,
  workspaceStixCoreObjects: PropTypes.array,
  simple: PropTypes.bool,
  targetStixCoreObjectTypes: PropTypes.array,
  onTypesChange: PropTypes.func,
  onAdd: PropTypes.func,
  onDelete: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(InvestigationAddStixCoreObjects);
