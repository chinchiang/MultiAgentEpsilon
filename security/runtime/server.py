"""可信啟動入口，只在無網路候選容器內執行。

Trusted entry point, executed only inside the networkless candidate container."""
import json
import sys
import uvicorn

settings = json.load(open('/run/fixture.json'))
sys.path.insert(0, '/candidate')
from fixture_app.app import create_app

# variant 只在內建缺陷自我測試時出現。 / A variant is present only for the seeded-defect self-test.
options = {'variant': settings['variant']} if 'variant' in settings else {}
uvicorn.run(create_app(settings['dsn'], settings['schema'], **options),
            uds='/tmp/epsilon-http.sock', access_log=False, log_level='error')
