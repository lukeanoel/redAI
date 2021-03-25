import json
import string

import pandas as pd
import spacy
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer

from .data_svc import DataService


class CleaningService:

    def __init__(self):
        pass

    def split_into_words(self, text):
        tokens = word_tokenize(text)
        tokens = [w.lower() for w in tokens]
        # remove punctuation
        table = str.maketrans('', '', string.punctuation)
        stripped = [w.translate(table) for w in tokens]
        # remove remaining tokens that are not alphabetic
        words = [word for word in stripped if word.isalpha()]
        return words

    def filter_out_stop_words(self, words):
        stop_words = set(stopwords.words('english'))
        words = [w for w in words if not w in stop_words]
        return words

    def clean_text(self, text):
        return self.filter_out_stop_words(self.split_into_words(text))

    def clean_groups(self, json_file):
        with open(json_file) as f:
            groups_dict = json.load(f)

        for group in groups_dict['objects']:
            print(group)

    def spacy_test(self):
        group = DataService.get_group_json(group_name="APT1")
        nlp = spacy.load("en_core_web_sm")

        technique_str = ""
        for technique in group['techniques']:
            technique_str += technique[2]

        doc = nlp(technique_str)
        for token in doc:
            print(token.text)

    def bow_test(self):
        # group = DataService.get_group_json(group_name="APT1")
        # groups = DataService.get_groups_json()
        CountVec = CountVectorizer(ngram_range=(1, 1),  # to use bigrams ngram_range=(2,2)
                                   stop_words='english')

        f_techniques = open("models/training/techniques.txt", "r")
        f_groups = open("models/training/groups.txt", "r")
        f_malware = open("models/training/malware.txt", "r")
        technique_str = f_techniques.read()
        groups_str = f_groups.read()
        malware_str = f_malware.read()
        unstructured_txt = [technique_str, groups_str, malware_str]

        # without smooth IDF
        print("Without Smoothing:")
        # define tf-idf
        tf_idf_vec = TfidfVectorizer(use_idf=True,
                                     smooth_idf=False,
                                     ngram_range=(1, 1), stop_words='english')  # to use only  bigrams ngram_range=(2,2)
        # transform
        tf_idf_data = tf_idf_vec.fit_transform(unstructured_txt)

        # create dataframe
        tf_idf_dataframe = pd.DataFrame(tf_idf_data.toarray(), columns=tf_idf_vec.get_feature_names())
        print(tf_idf_dataframe)
        print("\n")

        # with smooth
        tf_idf_vec_smooth = TfidfVectorizer(use_idf=True,
                                            smooth_idf=True,
                                            ngram_range=(1, 1), stop_words='english')

        tf_idf_data_smooth = tf_idf_vec_smooth.fit_transform(unstructured_txt)

        print("With Smoothing:")
        tf_idf_dataframe_smooth = pd.DataFrame(tf_idf_data_smooth.toarray(),
                                               columns=tf_idf_vec_smooth.get_feature_names())
        print(tf_idf_dataframe_smooth)
