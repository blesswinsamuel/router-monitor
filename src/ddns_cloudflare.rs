use std::{thread, time::Duration};

use anyhow::{Context, Result};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsRecordResponse {
    name: String,
    content: String,
    #[serde(rename = "type")]
    record_type: String,
    id: String,
    ttl: u32,
    proxied: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct DnsRecordRequest {
    name: String,
    content: String,
    #[serde(rename = "type")]
    record_type: String,
    ttl: u32,
    proxied: bool,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct CurrentIPLabels {
    current_ip: String,
}

#[derive(Clone)]
pub struct DdnsCloudflare {
    ddns_cloudflare_api_token: String,
    ddns_cloudflare_email: String,
    ddns_cloudflare_domain: String,
    ddns_cloudflare_record: String,
    ddns_cloudflare_ttl: Duration,

    metric_current_ip: Family<CurrentIPLabels, Gauge>,
}

impl DdnsCloudflare {
    pub fn new(
        cloudflare_api_token: String,
        cloudflare_email: String,
        cloudflare_domain: String,
        cloudflare_record: String,
        cloudflare_ttl: Duration,
    ) -> Self {
        Self {
            ddns_cloudflare_api_token: cloudflare_api_token,
            ddns_cloudflare_email: cloudflare_email,
            ddns_cloudflare_domain: cloudflare_domain,
            ddns_cloudflare_record: cloudflare_record,
            ddns_cloudflare_ttl: cloudflare_ttl,

            metric_current_ip: Default::default(),
        }
    }

    pub fn register(&self, registry: &mut Registry) {
        registry.register("router_monitor_ddns_cloudflare_current_ip", "Current IP", self.metric_current_ip.clone());
    }

    pub fn start(&self) -> Result<()> {
        self.validate_api_token().context("validate_api_token failed")?;
        let zone_id = self.get_zone_id().context("get_zone_id failed")?;
        log::info!("cloudflare zone id: {}", zone_id);
        let mut current_dns_record = self.get_dns_record(&zone_id).context("get_dns_record failed")?;
        log::info!("current cloudflare dns record: {:?}", current_dns_record);
        loop {
            match self.update_ip(zone_id.clone(), current_dns_record.clone()) {
                Ok(new_dns_record) => {
                    current_dns_record = new_dns_record;
                }
                Err(e) => {
                    log::error!("update_ip failed: {:#}", e);
                }
            }
            thread::sleep(self.ddns_cloudflare_ttl);
        }
    }

    fn update_ip(&self, zone_id: String, current_dns_record: Option<DnsRecordResponse>) -> Result<Option<DnsRecordResponse>> {
        let ip = self.get_my_ip().context("get_ip failed")?;
        self.metric_current_ip.get_or_create(&CurrentIPLabels { current_ip: ip.clone() }).set(1);
        log::debug!("my_ip: {:?}", ip);
        let new_record = DnsRecordRequest {
            name: self.ddns_cloudflare_record.clone(),
            content: ip,
            record_type: "A".to_string(),
            ttl: self.ddns_cloudflare_ttl.as_secs() as u32,
            proxied: false,
        };
        log::debug!("new_record: {:?}", new_record);
        match current_dns_record {
            None => {
                let created_record = self.create_dns_record(&zone_id, &new_record).context("create_dns_record failed")?;
                log::info!("created dns record: {:?}", created_record);
                return Ok(Some(created_record));
            }
            Some(dns_record)
                if dns_record.content != new_record.content
                    || dns_record.ttl != new_record.ttl
                    || dns_record.proxied != new_record.proxied
                    || dns_record.record_type != new_record.record_type =>
            {
                let updated_record = self.update_dns_record(&zone_id, &dns_record.id, &new_record).context("update_dns_record failed")?;
                log::info!("updated dns record: {:?}", updated_record);
                return Ok(Some(updated_record));
            }
            Some(_) => {
                log::debug!("no need to update dns record");
                return Ok(current_dns_record);
            }
        };
    }

    fn get_my_ip(&self) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        let resp = client.get("https://api.ipify.org").send().context("request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("invalid response: {} (body: {:?})", resp.status(), resp.text()?));
        }
        Ok(resp.text()?)
    }

    fn validate_api_token(&self) -> Result<()> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .get("https://api.cloudflare.com/client/v4/user/tokens/verify")
            .header("X-Auth-Email", self.ddns_cloudflare_email.clone())
            .header("Authorization", format!("Bearer {}", self.ddns_cloudflare_api_token))
            .header("Content-Type", "application/json")
            .send()
            .context("request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("invalid response: {} (body: {:?})", resp.status(), resp.text()?));
        }
        Ok(())
    }

    fn get_zone_id(&self) -> Result<String> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .get(format!("https://api.cloudflare.com/client/v4/zones?name={}", self.ddns_cloudflare_domain))
            .header("X-Auth-Email", self.ddns_cloudflare_email.clone())
            .header("Authorization", format!("Bearer {}", self.ddns_cloudflare_api_token))
            .header("Content-Type", "application/json")
            .send()
            .context("request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("invalid response: {} (body: {:?})", resp.status(), resp.text()?));
        }
        #[derive(Serialize, Deserialize, Debug)]
        struct ZoneResponseResult {
            id: String,
        }
        #[derive(Serialize, Deserialize, Debug)]
        struct ZoneResponse {
            result: Vec<ZoneResponseResult>,
        }
        let body = resp.json::<serde_json::Value>().context("failed to parse zone id response")?;
        let body =
            serde_json::from_value::<ZoneResponse>(body.clone()).context("failed to parse zone id response into ZoneResponse struct")?;
        if body.result.len() == 0 {
            return Err(anyhow::anyhow!("zone id not found"));
        }
        Ok(body.result[0].id.clone())
    }

    fn get_dns_record(&self, zone_id: &str) -> Result<Option<DnsRecordResponse>> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .get(format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records?name={}", zone_id, self.ddns_cloudflare_record))
            .header("X-Auth-Email", self.ddns_cloudflare_email.clone())
            .header("Authorization", format!("Bearer {}", self.ddns_cloudflare_api_token))
            .header("Content-Type", "application/json")
            .send()
            .context("request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("invalid response: {} (body: {:?})", resp.status(), resp.text()?));
        }
        #[derive(Serialize, Deserialize, Debug)]
        struct DnsRecordResponseWithResult {
            result: Vec<DnsRecordResponse>,
        }
        let body = resp.json::<serde_json::Value>().context("failed to parse dns record response")?;
        let body = serde_json::from_value::<DnsRecordResponseWithResult>(body.clone())
            .context("failed to parse dns record response into DnsRecordResponse struct")?;
        return Ok(body.result.first().cloned());
    }

    fn create_dns_record(&self, zone_id: &str, record: &DnsRecordRequest) -> Result<DnsRecordResponse> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", zone_id,))
            .header("X-Auth-Email", self.ddns_cloudflare_email.clone())
            .header("Authorization", format!("Bearer {}", self.ddns_cloudflare_api_token))
            .json(record)
            .send()
            .context("request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("invalid response: {} (body: {:?})", resp.status(), resp.text()?));
        }
        #[derive(Serialize, Deserialize, Debug)]
        struct DnsRecordResponseWithResult {
            result: DnsRecordResponse,
        }
        let body = resp.json::<serde_json::Value>().context("failed to parse dns record response")?;
        let body = serde_json::from_value::<DnsRecordResponseWithResult>(body.clone())
            .context("failed to parse dns record response into DnsRecordResponse struct")?;
        return Ok(body.result);
    }

    fn update_dns_record(&self, zone_id: &str, record_id: &str, record: &DnsRecordRequest) -> Result<DnsRecordResponse> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .put(format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}", zone_id, record_id,))
            .header("X-Auth-Email", self.ddns_cloudflare_email.clone())
            .header("Authorization", format!("Bearer {}", self.ddns_cloudflare_api_token))
            .json(record)
            .send()
            .context("request failed")?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("invalid response: {} (body: {:?})", resp.status(), resp.text()?));
        }
        #[derive(Serialize, Deserialize, Debug)]
        struct DnsRecordResponseWithResult {
            result: DnsRecordResponse,
        }
        let body = resp.json::<serde_json::Value>().context("failed to parse dns record response")?;
        let body = serde_json::from_value::<DnsRecordResponseWithResult>(body.clone())
            .context("failed to parse dns record response into DnsRecordResponse struct")?;
        return Ok(body.result);
    }
}
