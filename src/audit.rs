//! The module for the Wasmtime CLI audits.

use anyhow::{bail, Result, Error};
use rustsec::Report;
use std::path::Path;
use wasmshield::sbom::sbom_audit;
use wasmshield::decompose::{decompose, clean_extracted, get_name};
use wasmshield::signature::verify;


/// Some function
pub fn audit_process(bytes: &[u8]) -> Result<(), Error> {

    // SIGNATURE Check

    use std::io::{stdin,stdout,Write};
    let mut path=String::new();
    print!("Please enter the path to the key: ");
    let _=stdout().flush();
    stdin().read_line(&mut path).expect("Did not enter a correct string");
    if let Some('\n')=path.chars().next_back() {
        path.pop();
    }
    if let Some('\r')=path.chars().next_back() {
        path.pop();
    }

    let signature = signature_check(bytes, Path::new(&path));

    match signature {
        Ok(()) => {},
        Err(err) => {
            bail!("Signature verification failed: {}", err)
        }
    }

    // SBOM Check
    let sbom = sbom_check(bytes);

    match sbom {
        Ok(()) => {},
        Err(err) => {
            bail!("SBOM verification failed: {}", err)
        }
    }

    Ok(())
}

fn sbom_check(bytes: &[u8]) -> Result<(), Error> {
    let mut vuln_flag = false;
    let mut warn_flag = false;
    match helper_audit(bytes) {
        Ok(reports) => {
            for report in reports {
                let name = report.0;
                let report = report.1;
                println!("Component: {}", name);
                if report.vulnerabilities.count != 0 {
                    vuln_flag = true;
                    for vuln in report.vulnerabilities.list {
                        println!("Vulnerability advisory: {}", vuln.advisory.title);
                        println!("Package: {}", vuln.package.name.as_str());
                    }
                }
                else if report.warnings.len() != 0 {
                    warn_flag = true;
                    for (_, warns) in report.warnings {
                        for warn in warns {
                            println!("Warning type: {:?}", warn.kind);
                            println!("Package: {:?}", warn.package.name.as_str())
                        }
                    }
                }
            }
        },
        Err(err) => {
            bail!("Something went wrong: {}", err)
        }
    }
    
    if vuln_flag || warn_flag {
        bail!("We found some vulnerabilities or warnings!")
    } 
    Ok(())
}

fn signature_check(bytes: &[u8], key_path: &Path) -> Result<(), Error> {
    let mut flag = false;

    match helper_signature(bytes, key_path) {
        Ok(verifications) => {
            for verification in verifications {
                match verification.1 {
                    Some(err) => {
                        flag = true;
                        eprintln!("{} failed signature check {}", verification.0, err)
                    }
                    _ => {}
                }
            }
        }
        Err(err) => {
            eprintln!("Error occured while auditing component: {}", err);
            std::process::exit(1);
        }
    }
    if !flag {
        Ok(())
    }
    else {
        bail!("Signatures where not valid")
    }
}

fn helper_audit(bytes: &[u8]) -> Result<Vec<(String, Report)>> {
    let components = wasmshield::decompose::decompose(&bytes);
    let mut reports = Vec::new();
    // Given the way decomposition is implemented, the first component in the list is always the entire
    // component. This is useful for checking signatures but in this case, we don't want to show the
    // same dependency report twice. We can therefore always skip the first component as it
    // is the same dependency info as the second component.
    let skip = 0;
    let mut counter = 0;
    for component in components {
        let name = if counter == 0 {"composition".to_string()} else {wasmshield::decompose::get_name(&component)};
        // Skip the skipth component in the component list to avoid redundant reports
        if skip != counter {
            match sbom_audit(&component, None) {
                Ok(report) => {
                    reports.push((name, report));
                },
                Err(err) => {
                    bail!("Something went wrong during the verification of one of the components: {}", err)
                }
            }
        }
        counter += 1;
    }
    Ok(reports)
}

fn helper_signature(bytes: &[u8], key_path: &Path) -> Result<Vec<(String, Option<Error>)>, Error>  {

    let components = decompose(&bytes);
    let mut verifications = Vec::new();
    // Given the way decomposition is implemented, the first component in the list is always the entire
    // component. This is useful for checking signatures but in this case, we don't want to clean the first
    // component as it would invalidate its digest so we only call clean_extracted() on the subcomponents
    let skip = 0;
    let mut counter = 0;
    for mut component in components {
        if skip != counter { component = clean_extracted(&component) }

        let name = if counter == 0 {"composition".to_string()} else {get_name(&component)};
        match verify(&component, key_path) {
            Ok(_) => {
                verifications.push((name, None));
            },
            Err(err) => {
                verifications.push((name, Some(err)))
            }
        }
        counter += 1; 
    }
    Ok(verifications)
}