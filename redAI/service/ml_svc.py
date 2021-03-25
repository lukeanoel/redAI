import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from IPython.display import display
from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.feature_selection import chi2
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC


class MachineLearningService:
    def __init__(self):
        pass

    def build_model(self):
        df = pd.read_csv("models/data/data.csv")
        df.head()
        df.info()
        columns = ["name", "description", "label"]
        df = df[columns]
        df.columns
        df["label_id"] = df['label'].factorize()[0]
        label_id_df = df[['label', 'label_id']].drop_duplicates().sort_values('label_id')
        label_to_id = dict(label_id_df.values)
        id_to_label = dict(label_id_df[['label_id', 'label']].values)
        fig = plt.figure(figsize=(8, 6))  # uncomment to see totals of each category
        df.groupby('label').description.count().plot.bar(ylim=0)
        plt.show()
        tfidf = TfidfVectorizer(sublinear_tf=True, min_df=5, norm='l2', encoding='latin-1', ngram_range=(1, 2),
                                stop_words='english')

        features = tfidf.fit_transform(df.description).toarray()
        labels = df.label_id
        features.shape

        N = 2
        for label, label_id in sorted(label_to_id.items()):
            features_chi2 = chi2(features, labels == label_id)
            indices = np.argsort(features_chi2[0])
            feature_names = np.array(tfidf.get_feature_names())[indices]
            unigrams = [v for v in feature_names if len(v.split(' ')) == 1]
            bigrams = [v for v in feature_names if len(v.split(' ')) == 2]
            print("# '{}':".format(label))
            print("  . Most correlated unigrams:\n       . {}".format('\n       . '.join(unigrams[-N:])))
            print("  . Most correlated bigrams:\n       . {}".format('\n       . '.join(bigrams[-N:])))

            X_train, X_test, y_train, y_test = train_test_split(df['description'], df['label'],
                                                                random_state=0)
            count_vect = CountVectorizer()
            X_train_counts = count_vect.fit_transform(X_train)
            tfidf_transformer = TfidfTransformer()
            X_train_tfidf = tfidf_transformer.fit_transform(X_train_counts)

            clf = MultinomialNB().fit(X_train_tfidf, y_train)
            print(clf.predict(
                count_vect.transform(["Windows-based Trojan that was developed in the C programming language"])))

            models = [
                RandomForestClassifier(n_estimators=200, max_depth=3, random_state=0),
                LinearSVC(),
                MultinomialNB(),
                LogisticRegression(random_state=0),
            ]
            CV = 5
            cv_df = pd.DataFrame(index=range(CV * len(models)))
            entries = []
            for model in models:
                model_name = model.__class__.__name__
                accuracies = cross_val_score(model, features, labels, scoring='accuracy', cv=CV)
                for fold_idx, accuracy in enumerate(accuracies):
                    entries.append((model_name, fold_idx, accuracy))
            cv_df = pd.DataFrame(entries, columns=['model_name', 'fold_idx', 'accuracy'])

            sns.boxplot(x='model_name', y='accuracy', data=cv_df)
            sns.stripplot(x='model_name', y='accuracy', data=cv_df, size=8, jitter=True, edgecolor="gray", linewidth=2)
            plt.show()
            print(cv_df.groupby('model_name').accuracy.mean())

        # LinearSVC is the most accurate model
        model = LinearSVC()

        X_train, X_test, y_train, y_test, indices_train, indices_test = train_test_split(features, labels, df.index,
                                                                                         test_size=0.2,
                                                                                         random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        conf_mat = confusion_matrix(y_test, y_pred)
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(conf_mat, annot=True, fmt='d',
                    xticklabels=label_id_df.label.values, yticklabels=label_id_df.label.values)
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.show()

        for predicted in label_id_df.label_id:
            for actual in label_id_df.label_id:
                if predicted != actual and conf_mat[actual, predicted] >= 5:
                    print("'{}' predicted as '{}' : {} examples.".format(id_to_label[actual],
                                                                         id_to_label[predicted],
                                                                         conf_mat[actual, predicted]))
                    display(df.loc[indices_test[(y_test == actual) & (y_pred == predicted)]][
                                ['label', 'description']])
                    print('')

        print(metrics.classification_report(y_test, y_pred, target_names=df['label'].unique()))
