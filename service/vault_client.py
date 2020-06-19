import os

import hvac
import kubernetes
import jwt


class VaultClient():
    def __init__(self, vault_addr: str = None, github_token: str = None) -> None:
        if self._is_in_cluster():
            self._client = self._use_kubernetes_auth()
        else:
            self._client = self._use_github_auth(vault_addr, github_token)

    def ensure_has_value(self, secret_path: str) -> str:
        path = "/".join(secret_path.split("/")[:-1])
        secret = secret_path.split("/")[-1]

        return self._client.read(path)["data"][secret]

    def _is_in_cluster(self) -> bool:
        if "KUBERNETES_SERVICE_HOST" in os.environ:
            return True
        return False

    def _use_kubernetes_auth(self) -> hvac.Client:
        vault_addr = self._read_vault_addr()
        jwt_token = self._read_serviceaccount_token()

        decoded_token = jwt.decode(jwt_token, verify=False)
        namespace = decoded_token["kubernetes.io/serviceaccount/namespace"]
        serviceaccount_name = decoded_token["kubernetes.io/serviceaccount/service-account.name"]

        vault_client = hvac.Client(url=vault_addr)
        vault_client.auth_kubernetes(serviceaccount_name, jwt_token,
                                     mount_point=f"kubernetes/{namespace}/{serviceaccount_name}")

        return vault_client

    def _read_vault_addr(self) -> str:
        kubernetes.config.load_incluster_config()
        api_instance = kubernetes.client.CoreV1Api()

        response = api_instance.read_namespaced_config_map("vault", "vault")

        return response.data["vault_hostname"]

    def _read_k8s_secret(self, path: str, err_msg: str) -> str:
        if os.path.exists(path):
            with open(path) as fp:
                secret = fp.read()
            if len(secret) > 0:
                return secret

        raise Exception(err_msg)

    def _read_serviceaccount_token(self):
        return self._read_k8s_secret(
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            "If running on kubernetes, the pod must be running as a separate service account with its token loaded at /var/run/secrets/kubernetes.io/serviceaccount/token"
        )

    def _use_github_auth(self, vault_addr: str = None, github_token: str = None) -> hvac.Client:
        if vault_addr is None:
            if "VAULT_ADDR" not in os.environ:
                raise Exception("The environment variable VAULT_ADDR must be set or vault_addr given")
            vault_addr = os.environ["VAULT_ADDR"]
        if github_token is None:
            if "GITHUB_TOKEN" not in os.environ:
                raise Exception("The environment variable GITHUB_TOKEN must be set or github_token given")
            github_token = os.environ["GITHUB_TOKEN"]
        vault_client = hvac.Client(vault_addr)
        vault_client.auth.github.login(github_token)

        return vault_client
