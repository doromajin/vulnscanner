"""Log injection TP fixtures: AST-LOG-001 must fire."""
import logging
from flask import request

logger = logging.getLogger(__name__)


def handler_stdlib():
    user = request.args.get('user')
    logging.info("Login: " + user)      # AST-LOG-001 MEDIUM


def handler_logger_instance():
    action = request.form.get('action')
    logger.warning(action)              # AST-LOG-001 MEDIUM
