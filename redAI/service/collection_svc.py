import csv
import re


class CollectionService:
    def __init__(self, attack, data_svc):
        self.attack = attack
        self.data_svc = data_svc
        self.groups = attack.get_groups()

    def init_data_csv(self):
        collection_dict = {
            "group": [],
            "malware": [],
            "technique": [],
            "relationship": [],
            "course_of_action": []
        }

        # groups
        collected_groups = []
        for group in self.groups:
            group_dict = {"name": group.name, "description": ""}
            if 'description' in group:
                g_description = group.description
                find_pattern = re.compile('\[.*?\]\(.*?\)')  # get rid of att&ck reference (name)[link to site]
                m = find_pattern.findall(g_description)
                if len(m) > 0:
                    for j in m:
                        g_description = g_description.replace(j, '')
                        if g_description[0:2] == '\'s':
                            g_description = g_description[3:]
                        elif g_description[0] == ' ':
                            g_description = g_description[1:]
                find_pattern = re.compile('\(Citation.*?\)')  # get rid of att&ck reference (name)[link to site]
                m = find_pattern.findall(g_description)
                if len(m) > 0:
                    for j in m:
                        g_description = g_description.replace(j, '')
                        if g_description[0:2] == '\'s':
                            g_description = g_description[3:]
                        elif g_description[0] == ' ':
                            g_description = g_description[1:]
                group_dict["description"] = g_description
                collected_groups.append(group_dict)  # only add if a description exists
        collection_dict["group"] = collected_groups

        # malware
        collected_malware = []
        malware = self.attack.get_software()
        for mal in malware:
            mal_dict = {"name": mal.name, "description": ""}
            if 'description' in mal:
                m_description = mal.description
                find_pattern = re.compile('\[.*?\]\(.*?\)')  # get rid of att&ck reference (name)[link to site]
                m = find_pattern.findall(m_description)
                if len(m) > 0:
                    for j in m:
                        m_description = m_description.replace(j, '')
                        if m_description[0:2] == '\'s':
                            m_description = m_description[3:]
                        elif m_description[0] == ' ':
                            m_description = m_description[1:]
                find_pattern = re.compile('\(Citation.*?\)')  # get rid of att&ck reference (name)[link to site]
                m = find_pattern.findall(m_description)
                if len(m) > 0:
                    for j in m:
                        m_description = m_description.replace(j, '')
                        if m_description[0:2] == '\'s':
                            m_description = m_description[3:]
                        elif m_description[0] == ' ':
                            m_description = m_description[1:]
                mal_dict["description"] = m_description
                collected_malware.append(mal_dict)  # only add if a description exists
        collection_dict["malware"] = collected_malware

        # techniques
        collected_techniques = []
        techniques = self.attack.get_techniques()
        for technique in techniques:
            tech_dict = {"name": technique.name, "description": ""}
            if 'description' in technique:
                t_description = technique.description
                find_pattern = re.compile('\[.*?\]\(.*?\)')  # get rid of att&ck reference (name)[link to site]
                m = find_pattern.findall(t_description)
                if len(m) > 0:
                    for j in m:
                        t_description = t_description.replace(j, '')
                        if t_description[0:2] == '\'s':
                            t_description = t_description[3:]
                        elif t_description[0] == ' ':
                            t_description = t_description[1:]
                find_pattern = re.compile('\(Citation.*?\)')  # get rid of att&ck reference (name)[link to site]
                m = find_pattern.findall(t_description)
                if len(m) > 0:
                    for j in m:
                        t_description = t_description.replace(j, '')
                        if t_description[0:2] == '\'s':
                            t_description = t_description[3:]
                        elif t_description[0] == ' ':
                            t_description = t_description[1:]
                tech_dict["description"] = t_description.replace('<code>', '').replace('</code>', '').replace(
                    '\n', '').encode('ascii', 'ignore').decode('ascii')

                collected_techniques.append(tech_dict)  # only add if a description exists
        collection_dict["technique"] = collected_techniques

        # relationships
        collected_relationships = []
        for group in self.groups:
            relationships = self.attack.get_relationships_by_group_for_malware_use(group)
            for relationship in relationships:
                relationships_dict = {"name": self.attack.get(relationship.target_ref).name, "description": ""}
                if 'description' in relationship:
                    r_description = relationship.description
                    r_description = r_description.replace('<code>', '').replace('</code>', '').replace('"', "").replace(
                        ',', '').replace(
                        '\t', '').replace('  ', ' ').replace('\n', '').encode('ascii', 'ignore').decode('ascii')
                    find_pattern = re.compile('\[.*?\]\(.*?\)')  # get rid of att&ck reference (name)[link to site]
                    m = find_pattern.findall(r_description)
                    if len(m) > 0:
                        for j in m:
                            r_description = r_description.replace(j, '')
                            if r_description[0:2] == '\'s':
                                r_description = r_description[3:]
                            elif r_description[0] == ' ':
                                r_description = r_description[1:]
                    find_pattern = re.compile('\(Citation.*?\)')  # get rid of att&ck reference (name)[link to site]
                    m = find_pattern.findall(r_description)
                    if len(m) > 0:
                        for j in m:
                            r_description = r_description.replace(j, '')
                            if r_description[0:2] == '\'s':
                                r_description = r_description[3:]
                            elif r_description[0] == ' ':
                                r_description = r_description[1:]
                    # combine all the examples to one list
                    relationships_dict["description"] = r_description
                    collected_relationships.append(relationships_dict)  # only add if a description exists
        collection_dict["relationship"] = collected_relationships

        # courses of action
        collected_courses_of_action = []
        courses_of_action = self.attack.get_courses_of_action()
        for action in courses_of_action:
            course_dict = {"name": action.name, "description": ""}
            if 'description' in action:
                c_description = action.description
                find_pattern = re.compile('\[.*?\]\(.*?\)')  # get rid of att&ck reference (name)[link to site]
                m = find_pattern.findall(c_description)
                if len(m) > 0:
                    for j in m:
                        c_description = c_description.replace(j, '')
                        if c_description[0:2] == '\'s':
                            c_description = c_description[3:]
                        elif c_description[0] == ' ':
                            c_description = c_description[1:]
                course_dict["description"] = c_description
            collected_courses_of_action.append(course_dict)
        collection_dict["course_of_action"] = collected_courses_of_action

        # write to csv
        with open("models/data/data.csv", "w+", encoding="utf-8") as file:
            # writer = csv.writer(file, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
            fieldNames = ["name", "description", "label"]
            writer = csv.DictWriter(file, fieldnames=fieldNames)
            writer.writeheader()
            for label in collection_dict:
                for item in collection_dict[label]:
                    writer.writerow({"name": item["name"], "description": item["description"], "label": label})
