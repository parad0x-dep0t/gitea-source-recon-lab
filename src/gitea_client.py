import requests
import zipfile
import io
import os

class GiteaClient:
    def __init__(self, base_url, token=None):
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/v1"
        self.headers = {}

        if token:
            self.headers["Authorization"] = f"token {token}"

    def list_repositories(self):
        """
        List repositories accessible to the user.
        Works for both authenticated and unauthenticated access.
        """
        url = f"{self.api_url}/user/repos" if self.headers else f"{self.api_url}/repos/search"

        response = requests.get(url, headers=self.headers)

        if response.status_code != 200:
            raise Exception(f"Failed to list repositories: {response.text}")

        data = response.json()

        # Authenticated returns list directly
        if isinstance(data, list):
            return data

        # Unauthenticated search returns wrapped object
        return data.get("data", [])

    def download_repo(self, owner, repo_name, branch="main"):
        """
        Download repository as ZIP archive and extract it locally.
        """
        url = f"{self.api_url}/repos/{owner}/{repo_name}/archive/{branch}.zip"

        response = requests.get(url, headers=self.headers)

        if response.status_code != 200:
            raise Exception(f"Failed to download repo {repo_name}: {response.text}")

        extract_path = os.path.join("tmp_repos", repo_name)

        os.makedirs(extract_path, exist_ok=True)

        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall(extract_path)

        return extract_path
