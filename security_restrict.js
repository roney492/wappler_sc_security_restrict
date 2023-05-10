// Define the restricts function by Roney

async function restricts(opts) {
  const { auth, req, res } = this;
  const provider = auth[opts.provider];
  let roles = [];
  if (!provider) {
    throw new Error('Provider not found');
  }
  if (provider.identity === false) {
    if (opts.loginUrl) {
      if (req.fragment) {
        res.status(222).send(opts.loginUrl);
      } else {
        res.redirect(opts.loginUrl);
      }
    } else {
      if (provider.basicAuth) {
        res.set('WWW-Authenticate', `Basic Realm="${provider.basicRealm}"`);
      }
      res.sendStatus(401);
    }
    return;
  }
  // Dynamic Permissions
  const dynamicPermissions = Array.isArray(opts.dynamicPermissions) ?
    opts.dynamicPermissions :
    opts.dynamicPermissions.split(',').map(permission => permission.trim());
  if (opts.condition === 'OR') {

    for (let permission of dynamicPermissions) {
      if (!provider.perms[permission]) {
        if (opts.forbiddenUrl) {
          if (req.fragment) {
            res.status(222).send(opts.forbiddenUrl);
          } else {
            res.redirect(opts.forbiddenUrl);
          }
        } else {
          res.sendStatus(403);
        }
      }
      let perm = provider.perms[permission];
      let table = perm.table || provider.users.table;
      let ident = perm.identity || provider.users.identity;
      let roleColumn = perm.roleColumn || 'role'; // Assuming the role column is named 'role'

      let results = await provider.db
        .select(ident, roleColumn)
        .from(table)
        .where(ident, provider.identity)
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
        const role = results.map((result) => result.role);
        roles.push(...role);
        return true;
      } else {
        // Forbidden
        if (opts.forbiddenUrl) {
          if (req.fragment) {
            res.status(222).send(opts.forbiddenUrl);
          } else {
            res.redirect(opts.forbiddenUrl);
          }
        } else {
          res.sendStatus(403);
        }
      }
    }
    let cookieOptions = {
      domain: undefined,
      httpOnly: true,
      maxAge: (30) * 24 * 60 * 60 * 1000, // from days to ms
      path: '/',
      secure: true,
      sameSite: false
    };
    provider.app.setCookie('Roles', roles.join(','), cookieOptions)
  } else if (opts.condition === 'AND') {
    for (let permission of dynamicPermissions) {
      if (!provider.perms[permission]) {
        if (opts.forbiddenUrl) {
          if (req.fragment) {
            res.status(222).send(opts.forbiddenUrl);
          } else {
            res.redirect(opts.forbiddenUrl);
          }
        } else {
          res.sendStatus(403);
        }
      }
      let perm = provider.perms[permission];

      let table = perm.table || provider.users.table;
      let ident = perm.identity || provider.users.identity;
      let roleColumn = perm.roleColumn || 'role'; // Assuming the role column is named 'role'

      let results = await provider.db
        .select(ident, roleColumn)
        .from(table)
        .where(ident, provider.identity)
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
      const role = results.map((result) => result.role);
      roles.push(...role);
      if (results.length == 0) {
        // Forbidden
        if (opts.forbiddenUrl) {
          if (req.fragment) {
            res.status(222).send(opts.forbiddenUrl);
          } else {
            res.redirect(opts.forbiddenUrl);
          }
        } else {
          res.sendStatus(403);
        }
      }
    }
    let cookieOptions = {
      domain: undefined,
      httpOnly: true,
      maxAge: (30) * 24 * 60 * 60 * 1000, // from days to ms
      path: '/',
      secure: true,
      sameSite: false
    };
    provider.app.setCookie('Roles', roles.join(','), cookieOptions)
  } else {
    // Handle invalid condition
    throw new Error('Invalid condition specified');
  }
}

// Export the AuthProvider class and restricts function
module.exports = {
  restricts
};