// Define the restricts function by Roney

const App = require('../../../lib/core/app.js');
const app = new App();

async function restricts(opts) {

  if (this.auth[opts.provider].identity === false) {
    if (opts.loginUrl) {
      if (this.req.fragment) {
        this.res.status(222).send(opts.loginUrl);
      } else {
        this.res.redirect(opts.loginUrl);
      }
    } else {
      if (this.auth[opts.provider].basicAuth) {
        this.res.set('WWW-Authenticate', `Basic Realm="${this.auth[opts.provider].basicRealm}"`);
      }
      this.res.sendStatus(401);
    }
    return;
  }
  // Dynamic Permissions
  const dynamicPermissions = Array.isArray(opts.dynamicPermissions) ?
    opts.dynamicPermissions :
    opts.dynamicPermissions.split(',').map(permission => permission.trim());
  const provider = this.auth[opts.provider];
  if (opts.condition === 'OR') {
    for (let permission of dynamicPermissions) {
      if (this.auth[opts.provider].perms[permission]) {
        let perm = this.auth[opts.provider].perms[permission];
        let table = perm.table || this.auth[opts.provider].users.table;
        let ident = perm.identity || this.auth[opts.provider].users.identity;
        let roleColumn = perm.roleColumn || 'role'; // Assuming the role column is named 'role'
        let results = await this.auth[opts.provider].db
          .select(ident, roleColumn)
          .from(table)
          .where(ident, this.auth[opts.provider].identity)
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
      
        if (results.length) {
          const roles = results.map((result) => result.role);
        console.log(roles.join(','))
        let cookieOptions = {
          domain: options.domain || undefined,
          httpOnly: !!options.httpOnly,
          maxAge: options.expires === 0 ? undefined : (options.expires || 30) * 24 * 60 * 60 * 1000, // from days to ms
          path: options.path || '/',
          secure: !!options.secure,
          sameSite: options.sameSite || false
      };
        app.setCookie( 'Roles', roles.join(','), cookieOptions)
          return true;
        } else {
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
      }
    }
  } else if (opts.condition === 'AND') {
    for (let permission of dynamicPermissions) {
      if (this.auth[opts.provider].perms[permission]) {
        let perm = this.auth[opts.provider].perms[permission];

        let table = perm.table || this.auth[opts.provider].users.table;
        let ident = perm.identity || this.auth[opts.provider].users.identity;
        let roleColumn = perm.roleColumn || 'role'; // Assuming the role column is named 'role'
        let results = await this.auth[opts.provider].db
          .select(ident, roleColumn)
          .from(table)
          .where(ident, this.auth[opts.provider].identity)
          .where(function () {
            for (let condition of perm.conditions) {
              if (condition.operator == 'in') {
                this.whereIn(condition.column, condition.value);
              } else if (condition.operator == 'not in') {
                this.whereNotIn(condition.column, condition.value);
              } else if (condition.operator == 'is null') {
                this.whereNull(condition.column);
              } else if (condition.operator == 'is not null') {
                this.whereNotNull(condition.column);
              } else {
                this.where(condition.column, condition.operator, condition.value);
              }
            }
          });
        if (results.length == 0) {
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
        } else {
          const roles = results.map((result) => result.role);
        console.log(roles.join(','))
        // Define a simple parse function
function parse(options) {
  return options;
}
// Usage of setcookie function
app.setCookie({
  parse: parse,
  value: roles.join(','),
  expires: 30, // Expires in 30 days
  path: '/' // Set the appropriate path for the cookie
}, 'Roles');
          return true;
        }
      }
    }
  } else {
    // Handle invalid condition
    throw new Error('Invalid condition specified');
  }


}

// Export the AuthProvider class and restricts function
module.exports = {
  restricts
};