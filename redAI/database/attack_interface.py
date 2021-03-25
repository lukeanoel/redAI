from itertools import chain

from stix2 import Filter
from stix2.utils import get_type_from_id


class Attack:

    def __init__(self, src):
        self.src = src

    def get_related(self, src_type, rel_type, target_type, reverse=False):
        """build relationship mappings
           params:
             thesrc: MemoryStore to build relationship lookups for
             src_type: source type for the relationships, e.g "attack-pattern"
             rel_type: relationship type for the relationships, e.g "uses"
             target_type: target type for the relationship, e.g "intrusion-set"
             reverse: build reverse mapping of target to source
        """

        relationships = self.src.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', rel_type)
        ])

        # stix_id => [ { relationship, related_object_id } for each related object ]
        id_to_related = {}

        # build the dict
        for relationship in relationships:
            if (src_type in relationship.source_ref and target_type in relationship.target_ref):
                if (relationship.source_ref in id_to_related and not reverse) or (
                        relationship.target_ref in id_to_related and reverse):
                    # append to existing entry
                    if not reverse:
                        id_to_related[relationship.source_ref].append({
                            "relationship": relationship,
                            "id": relationship.target_ref
                        })
                    else:
                        id_to_related[relationship.target_ref].append({
                            "relationship": relationship,
                            "id": relationship.source_ref
                        })
                else:
                    # create a new entry
                    if not reverse:
                        id_to_related[relationship.source_ref] = [{
                            "relationship": relationship,
                            "id": relationship.target_ref
                        }]
                    else:
                        id_to_related[relationship.target_ref] = [{
                            "relationship": relationship,
                            "id": relationship.source_ref
                        }]
        # all objects of relevant type
        if not reverse:
            targets = self.src.query([
                Filter('type', '=', target_type),
            ])
        else:
            targets = self.src.query([
                Filter('type', '=', src_type),
            ])

        # remove revoked and deprecated objects from output
        # targets = list(
        # filter(
        # lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
        # stix_objects
        # )
        # )

        # build lookup of stixID to stix object
        id_to_target = {}
        for target in targets:
            id_to_target[target.id] = target

        # build final output mappings
        output = {}
        for stix_id in id_to_related:
            value = []
            for related in id_to_related[stix_id]:
                if not related["id"] in id_to_target:
                    continue  # targeting a revoked object
                value.append({
                    "object": id_to_target[related["id"]],
                    "relationship": related["relationship"]
                })
            output[stix_id] = value
        return output

    def get_groups(self):
        return self.src.query([Filter("type", "=", "intrusion-set")])

    # technique:group
    def techniques_used_by_groups(self):
        """returns group_id => {technique, relationship} for each technique used by the group."""
        return self.get_related("intrusion-set", "uses", "attack-pattern")

    def groups_using_technique(self):
        """returns technique_id => {group, relationship} for each group using the technique."""
        return self.get_related("intrusion-set", "uses", "attack-pattern", reverse=True)

    def get_software(self):
        return list(chain.from_iterable(
            self.src.query(f) for f in [
                Filter("type", "=", "tool"),
                Filter("type", "=", "malware")
            ]
        ))

    def get_techniques(self):
        return list(chain.from_iterable(
            self.src.query(f) for f in [
                Filter("type", "=", "attack-pattern")
            ]
        ))

    def get_courses_of_action(self):
        return list(chain.from_iterable(
            self.src.query(f) for f in [
                Filter("type", "=", "course-of-action")
            ]
        ))

    def get_techniques_by_group_software(self, group_stix_id):
        group_uses = [
            r for r in
            self.src.relationships(group_stix_id, 'uses', source_only=True)
            if get_type_from_id(r.target_ref) in ['malware', 'tool']
        ]

        # get the technique stix ids that the malware, tools use
        software_uses = self.src.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.source_ref for r in group_uses])
        ])

        return self.src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('id', 'in', [r.target_ref for r in software_uses])
        ])

    def get_relationships(self):
        return list(chain.from_iterable(
            self.src.query(f) for f in [
                Filter("type", "=", "relationship")
            ]
        ))

    def get_relationships_by_group_for_malware_use(self, group_stix_id):
        group_uses = [
            r for r in
            self.src.relationships(group_stix_id, 'uses', source_only=True)
            if get_type_from_id(r.target_ref) in ['malware', 'tool']
        ]

        # get the technique stix ids that the malware, tools use
        return self.src.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.source_ref for r in group_uses]),
            Filter('target_ref', 'contains', 'attack-pattern')
        ])

    def get_technique_by_group_not_subtechniques(self, group_stix_id):
        group_uses = [
            r for r in
            self.src.relationships(group_stix_id, 'uses', source_only=True)
            if get_type_from_id(r.target_ref) in ['malware', 'tool']
        ]

        # get the technique stix ids that the malware, tools use
        software_uses = self.src.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.source_ref for r in group_uses])
        ])

        return self.src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', False),
            Filter('id', 'in', [r.target_ref for r in software_uses])
        ])

    def get_subtechniques_of_technique_by_group(self, group_stix_id, technique_id):
        group_uses = [
            r for r in
            self.src.relationships(group_stix_id, 'uses', source_only=True)
            if get_type_from_id(r.target_ref) in ['malware', 'tool']
        ]

        # get the technique stix ids that the malware, tools use
        software_uses = self.src.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.source_ref for r in group_uses])
        ])

        return self.src.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True),
            Filter('id', 'in', [r.target_ref for r in software_uses])
        ])

    def get_malware_used_by_group(self, group_stix_id):
        group_uses = [
            r for r in
            self.src.relationships(group_stix_id, 'uses', source_only=True)
            if get_type_from_id(r.target_ref) in ['malware', 'tool']
        ]

        # get the technique stix ids that the malware, tools use
        return self.src.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.source_ref for r in group_uses])
        ])

    def get_techniques_by_content(self, content):
        # Search techniques where a string appears in the description
        techniques = self.src.query([Filter('type', '=', 'attack-pattern')])
        return list(filter(lambda t: content.lower() in t.description.lower(), techniques))

    def get(self, stix_id):
        return self.src.get(stix_id)
