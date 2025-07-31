/**
 * Eleventy data file for vulnerability data layer with change detection
 */

const fs = require('fs');
const path = require('path');

module.exports = async function() {
  const cacheDir = path.join(process.cwd(), '.cache');
  const dbPath = path.join(cacheDir, 'vulns.db');
  
  // Return empty data if no cache exists
  if (!fs.existsSync(dbPath)) {
    console.log('No vulnerability cache found, returning empty dataset');
    return {
      vulnerabilities: [],
      metadata: {
        count: 0,
        generated_at: new Date().toISOString(),
        source: 'empty_cache'
      }
    };
  }
  
  try {
    // Use Python script to extract data from SQLite cache
    const { spawn } = require('child_process');
    
    return new Promise((resolve, reject) => {
      const python = spawn('python', ['-c', `
import sys
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Add scripts to path
sys.path.append('scripts')

try:
    from processing.cache_manager import CacheManager
    
    cache_manager = CacheManager(db_path='${dbPath}')
    vulnerabilities = cache_manager.get_recent_vulnerabilities(limit=1000, min_risk_score=70)
    
    # Convert to summary format
    data = {
        'vulnerabilities': [v.to_summary_dict() for v in vulnerabilities],
        'metadata': {
            'count': len(vulnerabilities),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'source': 'cache_manager',
            'cache_stats': cache_manager.get_cache_stats()
        }
    }
    
    print(json.dumps(data))
    
except Exception as e:
    # Fallback: return empty data
    fallback_data = {
        'vulnerabilities': [],
        'metadata': {
            'count': 0,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'source': 'error_fallback',
            'error': str(e)
        }
    }
    print(json.dumps(fallback_data))
`]);

      let output = '';
      let error = '';
      
      python.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      python.stderr.on('data', (data) => {
        error += data.toString();
      });
      
      python.on('close', (code) => {
        try {
          if (code === 0 && output.trim()) {
            const data = JSON.parse(output.trim());
            console.log(`Loaded ${data.metadata.count} vulnerabilities from cache`);
            resolve(data);
          } else {
            console.warn('Python script failed, returning empty data:', error);
            resolve({
              vulnerabilities: [],
              metadata: {
                count: 0,
                generated_at: new Date().toISOString(),
                source: 'python_error',
                error: error
              }
            });
          }
        } catch (parseError) {
          console.warn('Failed to parse Python output, returning empty data:', parseError);
          resolve({
            vulnerabilities: [],
            metadata: {
              count: 0,
              generated_at: new Date().toISOString(),
              source: 'parse_error',
              error: parseError.message
            }
          });
        }
      });
    });
    
  } catch (error) {
    console.warn('Error loading vulnerability data:', error);
    return {
      vulnerabilities: [],
      metadata: {
        count: 0,
        generated_at: new Date().toISOString(),
        source: 'error',
        error: error.message
      }
    };
  }
};