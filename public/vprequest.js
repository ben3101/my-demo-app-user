let params = new URLSearchParams(location.search);
let user = params.get('user');
let application = params.get('application');
let vcissuer = params.get('vcissuer');
let nonce = params.get('nonce');
let domain = params.get('domain');
let redirect_uri = params.get('redirect_uri');
let code = params.get('code');

window.setTimeout(()=>{
  vp_approval();
}, 1000);

async function vp_approval(){
  let approved = confirm(`Please confirm you would like to create a VP with the following information: \n\nUser: ${user} \nApplication: ${application} \nIssuer: ${vcissuer}\nDomain:${domain}`);
  if(approved){
    await tryCreateVP();
  }else{
    alert('VP not granted.');
    window.location.href = `${redirect_uri}`;
  }
}

async function tryCreateVP(){
  let url = 'http://localhost:8081/create_vp';
    let response = await fetch(url, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json"
       },
      body: JSON.stringify({
        user: user,
        application: application,
        vcissuer: vcissuer,
        nonce: nonce,
        domain: domain,
        code: code
      })
    });
    let VP = await response.text();
    if(!(response.status === 200)){
      alert('Error generating VP. Returning to App.');
      window.location.href = `${redirect_uri}`;
    }else{
      alert('VP granted. Redirecting to App...');
      window.location.href = `${redirect_uri}?vp=${VP}`;
    }
}

