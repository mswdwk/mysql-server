({
  handshake: {
    auth: {
      username: 'someuser',
      password: 'somepass',
      certificate: {
        issuer:
            '/C=IN/ST=Karnataka/L=Bengaluru/O=Oracle/OU=MySQL/CN=MySQL CRL test ca certificate',
        subject:
            '/C=IN/ST=Karnataka/L=Bengaluru/O=Oracle/OU=MySQL/CN=MySQL CRL test client certificate',
      },
    }
  },
  stmts: function() {
    return {
      error: {}
    }
  }
})
