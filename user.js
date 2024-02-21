import express from 'express';
import cors from 'cors';
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt} from 'did-jwt-vc'
import { ES256KSigner, hexToBytes } from 'did-jwt';

//details that the app will check for before allowing VP
const appName = 'my-demo-app';
const userID = 'did:web:ben3101.solidcommunity.net';
const issuerID = 'did:web:issuer123.solidcommunity.net';
//trusted uri for the App
const trusted_uri = "http://localhost:8080/";
//a code is generated when redirecting to the vprequest.html page
//this code is required when a request is sent to the create_vp endpoint
let validCodes = [];
//create server to listen to http requests on port 8081
const app = express();
const port = 8081;
//middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded());
app.use((req, res, next)=>{
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    res.header('Access-Control-Allow-Methods', 'POST, GET, PATCH, DELETE, OPTIONS');
    next();
});
app.use(express.static('public'));

//redirect
app.post('/vprequest', async (req, res) => {
  console.log("Received VP Request at "+(Date.now()));
  const {user, vcissuer, application, nonce, domain, redirect_uri} = req.body;
  console.log(`\nuser: ${user}\nissuer: ${vcissuer}\napp: ${application}\nnonce: ${nonce}\ndomain: ${domain}\nredirect_uri: ${redirect_uri}`);
  //check if VP can be made for the given details, and the URI matches the trusted URI for this app. 
  if((application === appName && user === userID && vcissuer === issuerID && 
    redirect_uri.substring(0,trusted_uri.length) === trusted_uri)){
    const crypto = import('crypto');
    const code = (await crypto).randomBytes(16).toString('base64');
    validCodes.push(code);
    console.log(`Redirecting to /vprequest.html?user=${user}&application=${application}&vcissuer=${vcissuer}&nonce=${nonce}&domain=${domain}&redirect_uri=${redirect_uri}&code=${code} for confirmation.`);
    let url = `/vprequest.html?user=${user}&application=${application}&vcissuer=${vcissuer}&nonce=${encodeURIComponent(nonce)}&domain=${domain}&redirect_uri=${redirect_uri}&code=${encodeURIComponent(code)}`;
    res.redirect(url);
  }else{
      res.status(401).send('Unable to create a VP with those details.')
  }
});

//from html page, this is called and a VP is returned
app.post('/create_vp', async (req, res) => {
  const {user, vcissuer, application, nonce, domain, code} = req.body;
  if(!validCodes.includes(code)){
    console.log('Code given: '+code+' does is not valid');
    console.log('Valid Codes:'+validCodes);
    res.status(403).send('Invalid code.');
  }else{
    console.log("Creating VC...");
    const VC = await createVC(vcissuer, user);
    console.log("\nCreating VP...");
    const VP = await createVP(VC, nonce, domain, user, application);
    console.log("VP (JWT):\n"+JSON.stringify(VP));
    console.log("\nSending VP back to app...");
    validCodes.pop(validCodes.indexOf(code));
    res.status(200).send(VP);
  }
});

app.listen(port, () => {
    console.log(`Server Established on Port ${port}\n`);
})


//VC/VP code----------------------------
async function createVC(issuer, user){
  // Create a signer by using a private key (hex).
//ben3101 key
//const VcIssuerKey = 'a17cb543a7fbf5493a9754c977826925a346964c5b292e9da31bb6940f698313';
//issuer123 key
const VcIssuerKey = '2143c4bd995378ce36bacfcfda2e39610f2809e349b4d25e7b7d2b5f1d82e6ae';
const VcSigner = ES256KSigner(hexToBytes(VcIssuerKey))

// Prepare an issuer (of VC)
const vcIssuer = {
    did: issuer,
    signer: VcSigner
}

//Create a VC:
//use today's date for issuance
let today = Math.ceil((Date.now() / 1000));
let tenYearsFromNow = today + 315569260;

//test dates for expired VC, make issuance 10 years ago and expiry yesterday
// tenYearsFromNow = today - 86400;
// today = today - 315569260;
//-payload
const vcPayload = {
  sub: user,
  //nbf: 1562950282,
  nbf: today,
  exp: tenYearsFromNow,
  vc: {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://www.w3.org/2018/credentials/examples/v1"
    ],
    type: ["VerifiableCredential", "UniversityDegreeCredential"],
    credentialSubject: {
      degree: {
        type: "BachelorDegree",
        name: "Bachelor of Science"
      }
    }
  }
}
//console.log("VC payload:\n"+JSON.stringify(vcPayload));
//-convert VC to JWT
const vcJwt = await createVerifiableCredentialJwt(vcPayload, vcIssuer);
return vcJwt;
}
async function createVP(vc, nonce, domain, user, appName){
//Create a VP:
//the VC holder will sign the VP
//ben3101 key
const VpSignerKey = 'a17cb543a7fbf5493a9754c977826925a346964c5b292e9da31bb6940f698313';
//issuer123 key
//const VpSignerKey = '2143c4bd995378ce36bacfcfda2e39610f2809e349b4d25e7b7d2b5f1d82e6ae';
const VpSigner = ES256KSigner(hexToBytes(VpSignerKey))
const holder = {
  did: user,
  signer: VpSigner
}

//-VP payload
//set expiry time
let today = Math.ceil((Date.now() / 1000));
let fiveMinsFromNow = today + (5*60);
console.log('Now: '+today);
console.log('VP Expiry: '+fiveMinsFromNow);
const vpPayload = {
  vp: {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    verifiableCredential: [vc],
  },
  exp: fiveMinsFromNow,
  nonce: nonce,
  domain: domain,
  appName: appName
}
console.log("VP payload:\n"+JSON.stringify(vpPayload));
const vpJwt = await createVerifiablePresentationJwt(vpPayload, holder);
return vpJwt;
}