# Sigstore Example

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

## Signing our Model


```python
!sigstore sign --overwrite {model_file_name}
```


```python
%ls ./models/good-model/model.joblib*
```

### Verifying Model's Signature


```python
!sigstore verify identity \
    --bundle {model_file_name}.sigstore  \
    --cert-identity agm@seldon.io  \
    --cert-oidc-issuer https://accounts.google.com \
    --offline \
    {model_file_name}
```

### Tampering our Trained Model


```python
!cp ./models/good-model/model.joblib* ./models/tampered-model/
```


```python
tampered_file_name = "./models/tampered-model/model.joblib"
pwnd_pickle = b'\x80\x04\x95)\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x0eenv > pwnd.txt\x94\x85\x94R\x94.'
with open(tampered_file_name, 'wb') as f:
    f.write(pwnd_pickle)
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


```python
# %load ./runtime.py
from mlserver import MLModel
from mlserver.utils import get_model_uri
from mlserver.errors import MLServerError
from mlserver_sklearn import SKLearnModel, WELLKNOWN_MODEL_FILENAMES
from pydantic import BaseSettings, Extra

from sigstore_protobuf_specs.dev.sigstore.bundle.v1 import Bundle
from sigstore.verify import Verifier, VerificationMaterials
from sigstore.verify.policy import Identity

class SigstoreSettings(BaseSettings):
    """
    Parameters for Sigstore validation
    """

    class Config:
        env_prefix = "MLSERVER_SIGSTORE_"
        extra = Extra.allow

    bundle_path: str = ""
    cert_identity: str = ""
    cert_oidc_issuer: str = ""

class VerificationError(MLServerError):
    def __init__(self, model_name: str, reason: str):
        msg = f"Invalid signature for model '{model_name}': {reason}."
        super().__init__(msg)

class SigstoreModel(SKLearnModel):

    async def load(self):
        model_uri = get_model_uri(self._settings, WELLKNOWN_MODEL_FILENAMES)

        extra = settings.parameters or {}
        self._sigstore_settings = SigstoreSettings(**extra)
        self.verify()

        return await super().load()

    @property
    def _bundle(self) -> Bundle:
        with open(self._sigstore_settings.bundle_path, 'r') as bundle_file:
            return Bundle().from_json(bundle_file.read())

    @property
    def _materials(self) -> VerificationMaterials:
        model_uri = get_model_uri(self._settings, WELLKNOWN_MODEL_FILENAMES)
        with open(model_uri, 'rb') as model_file:
            artefact = model_file.read()
            materials = VerificationMaterials.from_bundle(
                input_=artefact,
                bundle=self._bundle,
                offline=True
            )

    def verify(self):
        verifier = Verifier.production()
        identity = Identity(
            identity=self._sigstore_settings.cert_identity,
            issuer=self._sigstore_settings.cert_oidc_issuer,
        )

        result = verifier.verify(
            self._materials,
            identity
        )

        if not result.success:
            raise VerificationError(self.name, result.reason)


```


```python
%%writefile models/settings.json
{
    "load_models_at_startup": false
}
```

Start MLServer on a separate terminal with:

```bash
mlserver start ./models
```

### List Available Models


```python
!curl -s -X POST -H 'Content-Type: application/json' localhost:8080/v2/repository/index -d '{}' | jq
```

### Load Good Model


```python
!curl -I -X POST localhost:8080/v2/repository/models/good-model/load 
```

### Load Tampered Model


```python
!curl -s -X POST localhost:8080/v2/repository/models/tampered-model/load | jq
```


```python

```
