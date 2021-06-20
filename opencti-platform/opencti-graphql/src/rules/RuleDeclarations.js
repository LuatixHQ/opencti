import AttributedToAttributedRule from './attributed-to-attributed/AttributedToAttributedRule';
import ObservableRelated from './observable-related/ObservableRelatedRule';
import AttributionUseRule from './attribution-use/AttributionUseRule';
import AttributionTargetsRule from './attribution-targets/AttributionTargetsRule';
import LocationTargetsRule from './location-targets/LocationTargetsRule';
import LocatedAtLocatedRule from './located-at-located/LocatedAtLocatedRule';

const declaredRules = [
  AttributedToAttributedRule,
  ObservableRelated,
  AttributionUseRule,
  AttributionTargetsRule,
  LocationTargetsRule,
  LocatedAtLocatedRule,
];
export default declaredRules;
