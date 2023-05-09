// Define the restricts function by Roney

const { setcookie } = require('../../../lib/modules/core.js');

async function restricts(opts) {
  
  if (this.auth.security.identity === false) {
    if (opts.loginUrl) {
      if (this.req.fragment) {
        this.res.status(222).send(opts.loginUrl);
      } else {
        this.res.redirect(opts.loginUrl);
      }
    } else {
      if (this.auth.security.basicAuth) {
        this.res.set('WWW-Authenticate', `Basic Realm="${this.auth.security.basicRealm}"`);
      }
      this.res.sendStatus(401);
    }
    return;
  }
  // Dynamic Permissions
  const dynamicPermissions = [opts.dynamicPermissions]; // Convert to array
  
  for (let permission of dynamicPermissions) {

    if (this.auth.security.perms[permission]) {
      let perm = this.auth.security.perms[permission];
      let table = perm.table || this.auth.security.users.table;
      let ident = perm.identity || this.auth.security.users.identity;
      let roleColumn = perm.roleColumn || 'role'; // Assuming the role column is named 'role'
      let results = await this.auth.security.db
        .select(ident, roleColumn)
        .from(table)
        .where(ident, this.auth.security.identity)
        .where(function () {
          for (let condition of perm.conditions) {
            if (condition.operator == 'in') {
              this.orWhereIn(condition.column, condition.value);
            } else if (condition.operator == 'not in') {
              this.orWhereNotIn(condition.column, condition.value);
            } else if (condition.operator == 'is null') {
              this.orWhereNull(condition.column);
            } else if (condition.operator == 'is not null') {
              this.orWhereNotNull(condition.column);
            } else {
              this.orWhere(condition.column, condition.operator, condition.value);
            }
          }
        });
        console.log(results)
        // setcookie({
        //   value: results[0].role,
        //   expires: 30, // Expires in 30 days
        //   path: '/' // Set the appropriate path for the cookie
        // }, 'Role');
      if (results.length) return true;
    }
  }

  // Forbidden
  if (opts.forbiddenUrl) {
    if (this.req.fragment) {
      this.res.status(222).send(opts.forbiddenUrl);
    } else {
      this.res.redirect(opts.forbiddenUrl);
    }
  } else {
    this.res.sendStatus(403);
  }
}

// Export the AuthProvider class and restricts function
module.exports = {
  restricts
};