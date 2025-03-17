#![allow(dead_code)]

use hickory_proto::{
    op::{Message, ResponseCode, header::MessageType, op_code::OpCode, query::Query},
    rr::{Name, RData, record_type::RecordType},
};
use std::{net::IpAddr, str::FromStr};

pub fn build_dns_query(domain: &str, query_type: RecordType, used_by_tcp: bool) -> Result<Vec<u8>, String> {
    let name = Name::from_str(domain).map_err(|e| e.to_string())?;
    let query = Query::query(name, query_type);
    let mut msg = Message::new();
    msg.add_query(query)
        .set_id(rand::Rng::random::<u16>(&mut rand::rng()))
        .set_op_code(OpCode::Query)
        .set_message_type(MessageType::Query)
        .set_recursion_desired(true);
    let mut msg_buf = msg.to_vec().map_err(|e| e.to_string())?;
    if used_by_tcp {
        let mut buf = (msg_buf.len() as u16).to_be_bytes().to_vec();
        buf.append(&mut msg_buf);
        Ok(buf)
    } else {
        Ok(msg_buf)
    }
}

pub fn extract_ipaddr_from_dns_message(message: &Message) -> Result<IpAddr, String> {
    if message.response_code() != ResponseCode::NoError {
        return Err(format!("{:?}", message.response_code()));
    }
    let mut cname = None;
    for answer in message.answers() {
        match answer.data().ok_or("DNS response not contains answer data")? {
            RData::A(addr) => {
                return Ok(IpAddr::V4((*addr).into()));
            }
            RData::AAAA(addr) => {
                return Ok(IpAddr::V6((*addr).into()));
            }
            RData::CNAME(name) => {
                cname = Some(name.to_utf8());
            }
            _ => {}
        }
    }
    if let Some(cname) = cname {
        return Err(cname);
    }
    Err(format!("{:?}", message.answers()))
}

pub fn extract_domain_from_dns_message(message: &Message) -> Result<String, String> {
    let query = message.queries().first().ok_or("DnsRequest no query body")?;
    let name = query.name().to_string();
    Ok(name)
}

pub fn parse_data_to_dns_message(data: &[u8], used_by_tcp: bool) -> Result<Message, String> {
    if used_by_tcp {
        if data.len() < 2 {
            return Err("invalid dns data".into());
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let data = data.get(2..len + 2).ok_or("invalid dns data")?;
        return parse_data_to_dns_message(data, false);
    }
    let message = Message::from_vec(data).map_err(|e| e.to_string())?;
    Ok(message)
}
