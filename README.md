# Sigstore Example

This example is part of a talk in [Supply Chain Security for MLSecOps](https://docs.google.com/presentation/d/1O2JZHj2DzwzSbZZLqyPbUZ6QlMKf4V1QuRcq4ok9baI/edit). 

The example will cover the following steps:

1. Training a simple Scikit-Learn model, serialising it with `joblib`.
2. Signing our model, and verifying manually the signature.
3. Implementing a [MLServer](https://mlserver.readthedocs.io/en/latest/) runtime which handles the verification during model load.

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

model_file_name = "./models/good-model/model.joblib"
joblib.dump(classifier, model_file_name)
```


```python
open(model_file_name, 'rb').read()
```

## Signing our Model

Now that we have a model artefact, the next step will be to sign our binary.
For this, we will use the [`sigstore` CLI](https://github.com/sigstore/sigstore-python), which will generate a set of files:

- A *.crt certificate.
- A *.sig signature.
- A *.sigstore bundle, which combines both.

Note that the signature also verifies that a particular ID was the one who created it. 
As ID, we will use our own Gmail account (which will be authenticated through Google's OIDC server ahead of creating the signature).


```python
!sigstore sign --overwrite {model_file_name}
```


```python
%ls ./models/good-model/model.joblib*
```

### Verifying Model's Signature

To validate that the signature does what it should, we will try to use it manually to verify the identity for our artefact.
As you can see, the `sigstore verify identity` command needs us to specify both our own identity, and the OIDC issuer for this identity (Google's in this case).


```python
!sigstore verify identity \
    --bundle {model_file_name}.sigstore  \
    --cert-identity agm@seldon.io  \
    --cert-oidc-issuer https://accounts.google.com \
    --offline \
    {model_file_name}
```

### Tampering our Trained Model

To also validate that the signature detects if the file has been tampered with, we will manually inject a malicious pickle within our model artefact.


```python
!cp ./models/good-model/model.joblib* ./models/tampered-model/
```


```python
tampered_file_name = "./models/tampered-model/model.joblib"
pwnd_pickle = b'\x80\x04\x95)\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x0eenv > pwnd.txt\x94\x85\x94R\x94.'
with open(tampered_file_name, 'wb') as f:
    f.write(pwnd_pickle)
```

As we can see below, this makes the verification fail with the following error:

```
Signature is invalid for input
```


```python
!sigstore verify identity \
    --bundle {tampered_file_name}.sigstore  \
    --cert-identity agm@seldon.io  \
    --cert-oidc-issuer https://accounts.google.com \
    --offline \
    {tampered_file_name}
```

## Verify Signature at Deployment time

Now that we have signed our artefact and validated that it does its job, we will build a [MLServer runtime](https://mlserver.readthedocs.io/en/latest/) that handles the signature verification at model load time.

MLServer greatly simplifies building a custom inference runtime to serve our models. In this case, we will extend the built-in Scikit-Learn runtime to also handle verification.
For the latter, we will leverage the [Python API exposed by the `sigstore` package](https://sigstore.github.io/sigstore-python/sigstore.html).

Note that this runtime is not production-ready, however it should be good to enough to showcase how signature verification could be enforced at serving time.


```python
# %load ./runtime.py
from mlserver import MLModel
from mlserver.utils import get_model_uri
from mlserver.errors import MLServerError
from mlserver_sklearn.sklearn import SKLearnModel, WELLKNOWN_MODEL_FILENAMES

from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import Bundle
from sigstore.verify import Verifier, VerificationMaterials
from sigstore.verify.policy import Identity

CERT_IDENTITY = "agm@seldon.io"
CERT_OIDC_ISSUER = "https://accounts.google.com"

class VerificationError(MLServerError):
    def __init__(self, model_name: str, reason: str):
        msg = f"Invalid signature for model '{model_name}': {reason}."
        super().__init__(msg)

class SigstoreModel(SKLearnModel):

    async def load(self):
        model_uri = await get_model_uri(
            self._settings, wellknown_filenames=WELLKNOWN_MODEL_FILENAMES
        )
        self.verify(model_uri)
        return await super().load()

    def _get_bundle(self, model_uri: str) -> Bundle:
        bundle_path = f"{model_uri}.sigstore"
        with open(bundle_path, 'r') as bundle_file:
            return Bundle().from_json(bundle_file.read())

    def _get_materials(self, model_uri: str) -> VerificationMaterials:
        with open(model_uri, 'rb') as model_file:
            bundle = self._get_bundle(model_uri)
            return VerificationMaterials.from_bundle(
                input_=model_file,
                bundle=bundle,
                offline=True
            )

    def verify(self, model_uri: str):
        verifier = Verifier.production()
        identity = Identity(
            identity=CERT_IDENTITY,
            issuer=CERT_OIDC_ISSUER,
        )

        materials = self._get_materials(model_uri)
        result = verifier.verify(
            materials,
            identity
        )

        if not result.success:
            raise VerificationError(self.name, result.reason)


```

Note that we will also add a small piece of config to MLServer to disable auto-loading all available models.
That way we will be able to load them separately to assess whether the tampered model gets rejected.


```python
%%writefile models/settings.json
{
    "load_models_at_startup": false
}
```

With all in place, the next step will be to start MLServer on a separate terminal with:

```bash
mlserver start ./models
```

### List Available Models

Now that MLServer is running on the background, we can send a request to list the available models.
As you can see, MLServer finds the two artefacts that we created previously:

- `good-model`: our original trained model, with the right signed artefact.
- `naive-model`: the model we tampered, which will be loaded without signature verification.
- `tampered-model`: the model we tampered, injecting malicious code into the Pickle.


```python
!curl -s -X POST -H 'Content-Type: application/json' localhost:8080/v2/repository/index -d '{}' | jq
```

### Load Good Model

We will start by testing the model we originally trained and signed.
As you can see below, the model gets loaded correctly - as expected.


```python
!curl -I -X POST localhost:8080/v2/repository/models/good-model/load 
```

### Load Naive Model

We will now load the tampered model without verifying its signature.
For this, we will just instruct MLServer to load the model with the base SKLearn runtime, which lacks the verification added by our custom runtime.


```python
!curl -I -X POST localhost:8080/v2/repository/models/naive-model/load 
```

As we can see, the model goes through as normal.
However, if we inspect the folder where MLServer is running, we will be able to see that it the malicious code we injected previously run and exposed our environment variables in a `pwnd.txt` file:


```python
!cat pwnd.txt
```

### Load Tampered Model

We will now try to load the tampered model which, as you below, will fail with the following error:

```
Signature is invalid for input
```


```python
!rm pwnd.txt
```


```python
!curl -s -X POST localhost:8080/v2/repository/models/tampered-model/load | jq
```

Thanks to the signature verification, we avoided to run the malicious code that we injected previously.


```python
!ls pwnd.txt
```
