// Deployment helper with leaked cloud credentials.
fn publish_artifact() {
    let access_key = "AKIAIOSFODNN7EXAMPLE"; // aegis:expect aws-access-key
    let aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // aegis:expect hardcoded-tf-secrets
    println!("{access_key} {aws_secret_key}");
}

const HOST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----"; // aegis:expect ssh-private-key

fn main() {
    publish_artifact();
}
