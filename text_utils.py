"""Taken and slightly modified from:
https://github.com/rohithramesh1991/Unsupervised-Text-Clustering/blob/master/Unsupervised_clustering.py"""
from typing import List

import nltk
import string
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

# Text pre-processing
"""removes punctuation, stopwords, and returns a list of the remaining words, or tokens"""

nltk.download('stopwords')
nltk.download('wordnet')


# Cleaning the text

def text_process(text):
    '''
    Takes in a string of text, then performs the following:
    1. Remove all punctuation
    2. Remove all stopwords
    3. Return the cleaned text as a list of words
    4. Remove words
    '''
    stemmer = WordNetLemmatizer()
    nopunc = [char for char in text if char not in string.punctuation]
    nopunc = ''.join([i for i in nopunc if not i.isdigit()])
    nopunc = [word.lower() for word in nopunc.split() if word not in stopwords.words('english')]
    return [stemmer.lemmatize(word) for word in nopunc]


# Vectorisation : -
def get_kmeans_prediction(X_train: List[str], k: int = 10) -> List[int]:
    tfidfconvert = TfidfVectorizer(analyzer=text_process, ngram_range=(1, 3)).fit(X_train)

    X_transformed = tfidfconvert.transform(X_train)

    # Clustering the training sentences with K-means technique

    modelkmeans = KMeans(n_clusters=k, init='k-means++', n_init=100)
    modelkmeans.fit(X_transformed)

    return modelkmeans.predict(X_transformed)
