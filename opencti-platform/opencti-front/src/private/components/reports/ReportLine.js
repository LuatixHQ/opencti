import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import {
  KeyboardArrowRightOutlined,
  DescriptionOutlined,
} from '@material-ui/icons';
import { compose, pathOr, take } from 'ramda';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';
import ItemStatus from '../../../components/ReportStatus';
import StixCoreObjectLabels from '../common/stix_core_objects/StixCoreObjectLabels';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class ReportLineComponent extends Component {
  render() {
    const {
      t, fd, classes, node, dataColumns, onLabelClick,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/reports/all/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <DescriptionOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                {pathOr('', ['createdBy', 'name'], node)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.labels.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                  onClick={onLabelClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.published.width }}
              >
                {fd(node.published)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.object_status.width }}
              >
                <ItemStatus
                  status={node.object_status}
                  label={t(
                    `report_status_${
                      node.object_status ? node.object_status : 0
                    }`,
                  )}
                  variant="inList"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                {take(1, pathOr([], ['objectMarking', 'edges'], node)).map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      variant="inList"
                      label={markingDefinition.node.definition}
                      color={markingDefinition.node.x_opencti_color}
                    />
                  ),
                )}
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

ReportLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
};

const ReportLineFragment = createFragmentContainer(ReportLineComponent, {
  node: graphql`
    fragment ReportLine_node on Report {
      id
      name
      object_status
      createdBy {
        node {
          name
        }
      }
      published
      objectMarking {
        edges {
          node {
            id
            definition
            color
          }
        }
      }
      objectLabel {
        edges {
          node {
            id
            value
            color
          }
        }
      }
    }
  `,
});

export const ReportLine = compose(
  inject18n,
  withStyles(styles),
)(ReportLineFragment);

class ReportLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <DescriptionOutlined />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.labels.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.published.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.object_status.width }}
              >
                <div className="fakeItem" style={{ width: '60%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.marking.width }}
              >
                <div className="fakeItem" style={{ width: 100 }} />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

ReportLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const ReportLineDummy = compose(
  inject18n,
  withStyles(styles),
)(ReportLineDummyComponent);
