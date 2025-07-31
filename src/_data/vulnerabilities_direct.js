/**
 * Direct vulnerability data loader that bypasses the cache layer
 * NIST-IG: Data integrity validation (SI-10)
 */

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

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
  
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY);
    
    // Query vulnerabilities directly
    const query = `
      SELECT 
        cve_id as cveId,
        title,
        severity,
        cvss_score as cvssScore,
        epss_percentile as epssPercentile,
        published_date as publishedDate,
        last_modified_date as lastModifiedDate,
        vendors,
        products,
        tags,
        description,
        attack_vector as attackVector,
        attack_complexity as attackComplexity,
        privileges_required as privilegesRequired,
        user_interaction as userInteraction,
        scope,
        confidentiality_impact as confidentialityImpact,
        integrity_impact as integrityImpact,
        availability_impact as availabilityImpact
      FROM vulnerabilities
      WHERE epss_percentile >= 70
      ORDER BY epss_percentile DESC, cvss_score DESC
      LIMIT 1000
    `;
    
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Error loading vulnerabilities:', err);
        db.close();
        resolve({
          vulnerabilities: [],
          metadata: {
            count: 0,
            generated_at: new Date().toISOString(),
            source: 'error',
            error: err.message
          }
        });
        return;
      }
      
      // Process rows
      const vulnerabilities = rows.map(row => {
        // Calculate risk score
        const cvss = parseFloat(row.cvssScore) || 0;
        const epss = parseFloat(row.epssPercentile) || 0;
        const riskScore = Math.round((cvss * 10) + (epss * 0.5));
        
        // Parse JSON fields
        let vendors = [];
        let products = [];
        let tags = [];
        
        try {
          vendors = JSON.parse(row.vendors || '[]');
          products = JSON.parse(row.products || '[]');
          tags = JSON.parse(row.tags || '[]');
        } catch (e) {
          // Ignore parse errors
        }
        
        return {
          ...row,
          vendors,
          products,
          tags,
          riskScore,
          vendor: vendors[0] || 'Unknown',
          product: products[0] || 'Unknown',
          // Add computed fields
          isKevListed: tags.includes('kev') || tags.includes('KEV'),
          isCritical: row.severity === 'CRITICAL',
          isHigh: row.severity === 'HIGH',
          // Format dates
          publishedDate: row.publishedDate,
          lastModifiedDate: row.lastModifiedDate
        };
      });
      
      db.close();
      
      console.log(`Loaded ${vulnerabilities.length} vulnerabilities from direct query`);
      
      resolve({
        vulnerabilities,
        metadata: {
          count: vulnerabilities.length,
          generated_at: new Date().toISOString(),
          source: 'direct_query',
          filters: {
            min_epss_percentile: 70
          }
        }
      });
    });
  });
};