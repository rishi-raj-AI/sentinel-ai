import warnings

import pytest


warnings.filterwarnings("ignore", category=pytest.PytestCollectionWarning, message="cannot collect test class 'TestCopilot'.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"fastapi\.testclient")
