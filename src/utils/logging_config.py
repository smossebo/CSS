# Logging configuration for CCS framework
# Provides structured logging for all operations

import logging
import logging.config
import json
import os
from datetime import datetime
from typing import Dict, Optional, Any
import traceback
from pathlib import Path

class CCSLogger:
    """Centralized logging for CCS framework with multiple output formats"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.log_dir = self.config.get('log_dir', 'logs')
        self._setup_logging()
        
        # Get logger instances
        self.main_logger = logging.getLogger('ccs')
        self.security_logger = logging.getLogger('ccs.security')
        self.performance_logger = logging.getLogger('ccs.performance')
        self.cloud_logger = logging.getLogger('ccs.cloud')
        self.error_logger = logging.getLogger('ccs.error')
        self.audit_logger = logging.getLogger('ccs.audit')
        
    def _setup_logging(self):
        """Setup comprehensive logging configuration"""
        
        # Create log directory
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Current timestamp for log files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        log_config = {
            'version': 1,
            'disable_existing_loggers': False,
            
            'formatters': {
                'standard': {
                    'format': '%(asctime)s [%(levelname)-8s] %(name)-20s: %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                },
                'detailed': {
                    'format': '%(asctime)s [%(levelname)-8s] %(name)s:%(lineno)d - %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                },
                'json': {
                    '()': 'ccs.utils.logging_config.JSONFormatter',
                    'fmt_keys': {
                        'timestamp': '%(asctime)s',
                        'level': '%(levelname)s',
                        'module': '%(name)s',
                        'message': '%(message)s',
                        'file': '%(filename)s',
                        'line': '%(lineno)d',
                        'function': '%(funcName)s'
                    },
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                },
                'audit': {
                    'format': '%(asctime)s | %(levelname)s | %(user)s | %(operation)s | %(status)s | %(details)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                }
            },
            
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'level': self.config.get('console_level', 'INFO'),
                    'formatter': 'standard',
                    'stream': 'ext://sys.stdout'
                },
                'file_main': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'level': 'DEBUG',
                    'formatter': 'detailed',
                    'filename': os.path.join(self.log_dir, 'ccs_main.log'),
                    'maxBytes': 10 * 1024 * 1024,  # 10MB
                    'backupCount': 5,
                    'encoding': 'utf8'
                },
                'file_error': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'level': 'ERROR',
                    'formatter': 'detailed',
                    'filename': os.path.join(self.log_dir, 'ccs_errors.log'),
                    'maxBytes': 5 * 1024 * 1024,  # 5MB
                    'backupCount': 3,
                    'encoding': 'utf8'
                },
                'file_json': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'level': 'INFO',
                    'formatter': 'json',
                    'filename': os.path.join(self.log_dir, f'ccs_structured_{timestamp}.jsonl'),
                    'maxBytes': 10 * 1024 * 1024,
                    'backupCount': 3,
                    'encoding': 'utf8'
                },
                'file_audit': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'level': 'INFO',
                    'formatter': 'audit',
                    'filename': os.path.join(self.log_dir, 'ccs_audit.log'),
                    'maxBytes': 5 * 1024 * 1024,
                    'backupCount': 3,
                    'encoding': 'utf8'
                },
                'file_performance': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'level': 'INFO',
                    'formatter': 'json',
                    'filename': os.path.join(self.log_dir, 'ccs_performance.log'),
                    'maxBytes': 5 * 1024 * 1024,
                    'backupCount': 3,
                    'encoding': 'utf8'
                }
            },
            
            'loggers': {
                'ccs': {
                    'handlers': ['console', 'file_main', 'file_json'],
                    'level': 'INFO',
                    'propagate': False
                },
                'ccs.security': {
                    'handlers': ['console', 'file_main', 'file_error', 'file_json'],
                    'level': 'INFO',
                    'propagate': False
                },
                'ccs.performance': {
                    'handlers': ['file_performance', 'file_json'],
                    'level': 'DEBUG',
                    'propagate': False
                },
                'ccs.cloud': {
                    'handlers': ['console', 'file_main'],
                    'level': 'INFO',
                    'propagate': False
                },
                'ccs.error': {
                    'handlers': ['file_error', 'file_json'],
                    'level': 'ERROR',
                    'propagate': False
                },
                'ccs.audit': {
                    'handlers': ['file_audit'],
                    'level': 'INFO',
                    'propagate': False
                }
            },
            
            'root': {
                'handlers': ['console'],
                'level': 'WARNING'
            }
        }
        
        # Apply configuration
        logging.config.dictConfig(log_config)
        
        # Add custom filters
        logging.getLogger('ccs.audit').addFilter(AuditFilter())
    
    def log_operation_start(self, operation: str, user: str = 'system', 
                           details: Dict = None):
        """Log start of an operation"""
        details = details or {}
        self.main_logger.info(
            f"Starting {operation}",
            extra={
                'operation': operation,
                'user': user,
                'details': json.dumps(details),
                'event': 'operation_start'
            }
        )
        
        # Audit log
        self.audit_logger.info(
            f"{operation} started",
            extra={
                'user': user,
                'operation': operation,
                'status': 'started',
                'details': json.dumps(details)
            }
        )
    
    def log_operation_end(self, operation: str, success: bool, 
                         user: str = 'system', metrics: Dict = None, 
                         details: Dict = None):
        """Log end of an operation"""
        details = details or {}
        metrics = metrics or {}
        
        status = 'success' if success else 'failure'
        level = logging.INFO if success else logging.ERROR
        
        self.main_logger.log(
            level,
            f"Completed {operation} - {status.upper()}",
            extra={
                'operation': operation,
                'user': user,
                'status': status,
                'metrics': json.dumps(metrics),
                'details': json.dumps(details),
                'event': 'operation_end'
            }
        )
        
        # Audit log
        self.audit_logger.info(
            f"{operation} completed",
            extra={
                'user': user,
                'operation': operation,
                'status': status,
                'details': json.dumps({
                    **details,
                    'metrics': metrics
                })
            }
        )
    
    def log_security_event(self, event: str, level: str = 'INFO', 
                          user: str = 'system', details: Dict = None):
        """Log security-related event"""
        details = details or {}
        
        log_method = getattr(self.security_logger, level.lower(), 
                            self.security_logger.info)
        
        log_method(
            f"Security: {event}",
            extra={
                'event': event,
                'user': user,
                'severity': level,
                'details': json.dumps(details),
                'category': 'security'
            }
        )
        
        # Also log to audit
        self.audit_logger.info(
            f"Security event: {event}",
            extra={
                'user': user,
                'operation': 'security_event',
                'status': 'logged',
                'details': json.dumps({
                    'event': event,
                    'severity': level,
                    **details
                })
            }
        )
    
    def log_performance_metric(self, operation: str, metric: str, 
                              value: float, context: Dict = None):
        """Log performance metric"""
        context = context or {}
        
        self.performance_logger.info(
            f"Performance: {operation}.{metric} = {value}",
            extra={
                'operation': operation,
                'metric': metric,
                'value': value,
                'context': json.dumps(context),
                'event': 'performance_metric'
            }
        )
    
    def log_cloud_operation(self, provider: str, operation: str, 
                           success: bool, duration: float = None,
                           user: str = 'system', details: Dict = None):
        """Log cloud API operation"""
        details = details or {}
        status = 'success' if success else 'failure'
        
        message = f"Cloud: {provider}.{operation} - {status.upper()}"
        if duration is not None:
            message += f" ({duration:.3f}s)"
        
        level = logging.INFO if success else logging.WARNING
        
        self.cloud_logger.log(
            level, message,
            extra={
                'provider': provider,
                'operation': operation,
                'user': user,
                'status': status,
                'duration': duration,
                'details': json.dumps(details),
                'event': 'cloud_operation'
            }
        )
    
    def log_error(self, error: Exception, context: Dict = None, 
                 user: str = 'system', traceback_info: bool = True):
        """Log error with context"""
        context = context or {}
        
        error_details = {
            'type': type(error).__name__,
            'message': str(error),
            'user': user,
            'context': context
        }
        
        if traceback_info:
            error_details['traceback'] = traceback.format_exc()
        
        self.error_logger.error(
            f"Error: {type(error).__name__}: {str(error)}",
            extra={
                'error_details': json.dumps(error_details),
                'event': 'error'
            }
        )
        
        # Also log to audit for critical errors
        if isinstance(error, (MemoryError, OSError, ValueError)):
            self.audit_logger.error(
                f"Critical error: {type(error).__name__}",
                extra={
                    'user': user,
                    'operation': 'error_handling',
                    'status': 'critical',
                    'details': json.dumps(error_details)
                }
            )
    
    def log_capacity_analysis(self, folder_path: str, file_count: int,
                             capacity_bits: int, protocol: Dict = None,
                             user: str = 'system'):
        """Log capacity analysis for a folder"""
        self.performance_logger.info(
            f"Capacity: {folder_path} - {file_count} files, "
            f"{capacity_bits} bits",
            extra={
                'folder': folder_path,
                'file_count': file_count,
                'capacity_bits': capacity_bits,
                'protocol': json.dumps(protocol or {}),
                'user': user,
                'event': 'capacity_analysis'
            }
        )
    
    def log_extraction_stats(self, stego_folder: str, files_processed: int,
                            success_rate: float, duration: float,
                            user: str = 'system'):
        """Log extraction statistics"""
        self.performance_logger.info(
            f"Extraction: {stego_folder} - {files_processed} files, "
            f"{success_rate:.1%}, {duration:.3f}s",
            extra={
                'stego_folder': stego_folder,
                'files_processed': files_processed,
                'success_rate': success_rate,
                'duration': duration,
                'user': user,
                'event': 'extraction_stats'
            }
        )
    
    def log_protocol_usage(self, protocol_id: str, operation: str,
                          success: bool, user: str = 'system', 
                          details: Dict = None):
        """Log protocol usage"""
        details = details or {}
        status = 'success' if success else 'failure'
        
        self.security_logger.info(
            f"Protocol: {protocol_id} for {operation} - {status.upper()}",
            extra={
                'protocol_id': protocol_id,
                'operation': operation,
                'user': user,
                'status': status,
                'details': json.dumps(details),
                'event': 'protocol_usage'
            }
        )
    
    def get_log_file_paths(self) -> Dict[str, str]:
        """Get paths to all log files"""
        return {
            'main': os.path.join(self.log_dir, 'ccs_main.log'),
            'errors': os.path.join(self.log_dir, 'ccs_errors.log'),
            'audit': os.path.join(self.log_dir, 'ccs_audit.log'),
            'performance': os.path.join(self.log_dir, 'ccs_performance.log'),
            'structured': os.path.join(self.log_dir, 'ccs_structured_*.jsonl')
        }


class JSONFormatter(logging.Formatter):
    """Custom formatter for JSON logs"""
    
    def __init__(self, fmt_keys: Dict[str, str] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fmt_keys = fmt_keys or {}
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        log_object = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'module': record.name,
            'message': record.getMessage(),
        }
        
        # Add extra fields
        if hasattr(record, 'event'):
            log_object['event'] = record.event
        
        # Add all extra attributes
        for key, value in record.__dict__.items():
            if key.startswith('_') or key in ['args', 'asctime', 'created', 
                                            'exc_info', 'exc_text', 'filename',
                                            'funcName', 'levelname', 'levelno',
                                            'lineno', 'module', 'msecs', 'message',
                                            'msg', 'name', 'pathname', 'process',
                                            'processName', 'relativeCreated', 
                                            'stack_info', 'thread', 'threadName']:
                continue
            
            if key not in log_object:
                log_object[key] = value
        
        # Handle JSON in details field
        if 'details' in log_object and isinstance(log_object['details'], str):
            try:
                log_object['details'] = json.loads(log_object['details'])
            except:
                pass
        
        return json.dumps(log_object)


class AuditFilter(logging.Filter):
    """Filter for audit logs"""
    
    def filter(self, record):
        # Ensure required fields for audit logs
        if not hasattr(record, 'user'):
            record.user = 'unknown'
        if not hasattr(record, 'operation'):
            record.operation = 'unknown'
        if not hasattr(record, 'status'):
            record.status = 'unknown'
        if not hasattr(record, 'details'):
            record.details = '{}'
        return True


# Global logger instance
_global_logger = None

def get_logger(config: Dict = None) -> CCSLogger:
    """Get global logger instance"""
    global _global_logger
    if _global_logger is None:
        _global_logger = CCSLogger(config)
    return _global_logger

def setup_logging(config: Dict = None):
    """Setup logging configuration"""
    return get_logger(config)
