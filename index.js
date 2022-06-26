#!/usr/bin/env node
'use strict';

import http from 'http';
import https from 'https';
import createProxyServer from 'http-proxy';
import ClientOAuth2 from 'client-oauth2';
import got from 'got';
import { v4 } from 'uuid';
import url from 'node:url';
import LRUCache from 'lru-cache';
import accesslog from 'access-log';
import fs from 'fs';
import 'dotenv/config';

const sessionstore = new LRUCache({ttl: 86400*1000, ttlAutopurge: true});
const KEY = Buffer.from(process.env.SECRET_KEY, 'base64');

const oa2c = new ClientOAuth2({
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  accessTokenUri: process.env.ACCESS_TOKEN_URI,
  authorizationUri: process.env.AUTHORIZATION_URI,
  redirectUri: process.env.REDIRECT_URI,
  scopes: process.env.SCOPES,
})


function parseCookies (request) {
  const list = {};
  const cookieHeader = request.headers?.cookie;
  if (!cookieHeader) return list;

  cookieHeader.split(`;`).forEach(function(cookie) {
      let [ name, ...rest] = cookie.split(`=`);
      name = name?.trim();
      if (!name) return;
      const value = rest.join(`=`).trim();
      if (!value) return;
      list[name] = decodeURIComponent(value);
  });

  return list;
}


const proxyConfig = {
  target: process.env.RP_TARGET,
};
const proxy = new createProxyServer(proxyConfig);

const rolere = /^CN=(rundeck-[^,]+),/i;

function handleAuthCB(req, res, cookies) {
  const queryData = url.parse(req.url, true).query;
  return oa2c.code.getToken(req.url)
    .then(function (user) {
      return got.get(
        user.sign({
          url: process.env.USERINFO_URI,
        })
      ).json();
    }).then((resp) => {
      let roles = [];

      resp.attributes.memberOf.forEach((e) => {
        let matchres = e.match(rolere);
        if (matchres != null) {
          roles.push(matchres[1]);
        }
      });
      let userinfos = {
        username: resp.attributes.sAMAccountName[0],
        roles,
        exipreAt: Date.now()+86400000,
      };
      sessionstore.set(queryData.state, userinfos);
      let returl = cookies['_oauth_return'] || '/';
      res.setHeader('Set-Cookie', [
        `_oauth_session=${queryData.state}; Max-Age=86400; Path=/; HttpOnly`,
        `_oauth_return=; Max-Age=-300; Path=/; HttpOnly`,
      ]);
      res.writeHead(302, {'Location': returl});
      res.end(`<a href="${returl}">/</a>`);
    }).catch((error) => {
      console.log(error);
      res.writeHead(500, {'content-type': 'application/json'})
      res.end(JSON.stringify(error));
    });
}


const app = (req, res) => {
  accesslog(req, res);
  const cookies = parseCookies(req);


  if (req.url.startsWith('/oauth/callback')) {
    handleAuthCB(req, res, cookies)
    return;
  }

  if (req.url.startsWith('/oauth/logout')) {
    res.setHeader('Set-Cookie', [`_oauth_session=; Max-Age=-86400; Path=/`,]);
    res.writeHead(302, {'Location': '/'});
    res.end(`<a href="/">/</a>`);
    return;
  }

  let sessionid = cookies['_oauth_session'];
  let sessdata = sessionstore.get(sessionid);

  if (sessionid == null || sessdata == null || sessdata['exipreAt'] < Date.now()) {
    const rdruri = oa2c.code.getUri({state: v4()});
    res.setHeader('Set-Cookie', [
      `_oauth_session=; Max-Age=-86400; Path=/`,
      `_oauth_return=${req.url}; Max-Age=300; Path=/`,
    ]);
    res.writeHead(302, {'Location': rdruri});
    res.end(`<a href="${rdruri}">${rdruri}</a>`);
    return;
  }

  // at this point user should be identified
  if (req.url.startsWith('/oauth/session')) {
    res.writeHead(200, {'content-type': 'application/json'})
    res.end(JSON.stringify(sessdata));
    return;
  } else {
      proxy.web(req, res, (err) => {
      res.writeHead(502);
      res.end("There was an error proxying your request");
    });
  }

};

proxy.on('proxyReq', (proxyReq, req, res, options) => {
  const cookies = parseCookies(req);
  let sessionid = cookies['_oauth_session'];
  let sessdata = sessionstore.get(sessionid);
  proxyReq.setHeader('X-Forwarded-Uuid', sessdata['username']);
  proxyReq.setHeader('X-Forwarded-Roles', sessdata['roles'].join(','));
});


let proxyServer = null;
let protocol = 'http';
if (process.env.CERT_FILE && process.env.KEY_FILE) {
  proxyServer = https.createServer({
      key: fs.readFileSync(process.env.KEY_FILE, 'utf8'),
      cert: fs.readFileSync(process.env.CERT_FILE, 'utf8')
    },
    app,
  );
  protocol = 'https';
} else {
  proxyServer = http.createServer(app);
}


proxyServer.on('upgrade', function (req, socket, head) {
  proxy.ws(req, socket, head);
});

const port = parseInt(process.env.PORT) || 3000;
proxyServer.listen(port, () => console.log(`listen on port ${port} as ${protocol}!\n`));