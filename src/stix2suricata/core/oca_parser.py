"""OCA bundle parser for x-oca-detection / x-oca-behavior objects"""

import base64
import logging
from typing import List, Dict

from stix2suricata.core.parser import StixPatternParser


class OCABundleParser:
    """Parses OCA extension bundles into indicator dicts for the existing pipeline.

    Handles x-oca-detection objects with base64-encoded STIX patterns,
    resolves detects relationships to x-oca-behavior for MITRE metadata.
    """

    def __init__(self):
        self.pattern_parser = StixPatternParser()
        self.logger = logging.getLogger(__name__)

    def parse_bundle(self, bundle: Dict) -> List[Dict]:
        """Parse an OCA bundle and return a list of indicator dicts."""
        objects = bundle.get('objects', [])
        obj_index = {o['id']: o for o in objects if 'id' in o}
        detects_map = self._build_detects_map(objects, obj_index)

        indicators = []
        for obj in objects:
            if obj.get('type') != 'x-oca-detection':
                continue
            parsed = self._parse_detection(obj, detects_map)
            indicators.extend(parsed)

        return indicators

    def _build_detects_map(self, objects: List[Dict], obj_index: Dict) -> Dict:
        """Return {detection_id: behavior_object} from detects relationships."""
        detects_map = {}
        for obj in objects:
            if (obj.get('type') == 'relationship'
                    and obj.get('relationship_type') == 'detects'):
                detection_id = obj.get('source_ref', '')
                behavior_id = obj.get('target_ref', '')
                if behavior_id in obj_index:
                    detects_map[detection_id] = obj_index[behavior_id]
        return detects_map

    def _parse_detection(self, detection: Dict, detects_map: Dict) -> List[Dict]:
        """Parse a single x-oca-detection object into indicator dicts."""
        analytic = detection.get('analytic', {})
        if analytic.get('type') != 'Stix Pattern':
            self.logger.warning(
                "Skipping detection %s: unsupported analytic type '%s'",
                detection.get('id'), analytic.get('type')
            )
            return []

        pattern = self._decode_pattern(detection)
        if pattern is None:
            return []

        behavior = detects_map.get(detection.get('id', ''))
        stix_metadata = self._build_metadata(detection, behavior)

        indicators = self.pattern_parser.parse(pattern)
        for indicator in indicators:
            indicator['stix_metadata'] = stix_metadata
        return indicators

    def _decode_pattern(self, detection: Dict):
        """Base64-decode the analytic.rule field. Returns None on error."""
        rule_b64 = detection.get('analytic', {}).get('rule', '')
        try:
            return base64.b64decode(rule_b64).decode('utf-8')
        except Exception as exc:
            self.logger.warning(
                "Skipping detection %s: base64 decode error: %s",
                detection.get('id'), exc
            )
            return None

    def _build_metadata(self, detection: Dict, behavior) -> Dict:
        """Build the stix_metadata dict from detection and optional behavior."""
        metadata = {
            'id': detection.get('id', ''),
            'name': detection.get('name', ''),
        }
        if behavior:
            metadata['technique'] = behavior.get('technique', '')
            metadata['tactic'] = behavior.get('tactic', '')
            metadata['description'] = behavior.get('description', '')
        return metadata
