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

