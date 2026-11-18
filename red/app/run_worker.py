import asyncio
import logging
import os
import signal
import sys
from app.outbox_worker import OutboxWorker
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('outbox-worker-daemon')

async def main():
    dsn = os.environ['POSTGRES_DSN']
    worker_id = os.getenv('WORKER_ID', f'worker-{os.getpid()}')
    logger.info(f'Initializing OutboxWorker daemon with ID: {worker_id}')
    worker = OutboxWorker(dsn=dsn, worker_id=worker_id)
    await worker.start()
    stop_event = asyncio.Event()

    def _trigger_shutdown():
        logger.info('Shutdown signal received, initiating graceful teardown...')
        stop_event.set()
    if sys.platform != 'win32':
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, _trigger_shutdown)
    else:

        def _sig_handler(sig, frame):
            _trigger_shutdown()
        signal.signal(signal.SIGINT, _sig_handler)
        signal.signal(signal.SIGTERM, _sig_handler)
    logger.info(f"OutboxWorker [{worker_id}] is actively polling and listening on channel 'gateway_outbox_trigger'.")
    try:
        await stop_event.wait()
    finally:
        await worker.stop()
        logger.info('OutboxWorker daemon exited cleanly.')
if __name__ == '__main__':
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass