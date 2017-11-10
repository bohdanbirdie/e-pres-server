const {authenticate} = require('feathers-authentication').hooks;
const commonHooks = require('feathers-hooks-common');
const {restrictToOwner} = require('feathers-authentication-hooks');
const ObjectID = require('mongodb').ObjectID;

const {hashPassword} = require('feathers-authentication-local').hooks;
const restrict = [// authenticate('jwt'),
  restrictToOwner({idField: '_id', ownerField: '_id'})];

const updateIDsInQuery = (obj) => {
  for (let i in obj) {
    if (typeof obj[i] == 'object') {
      updateIDsInQuery(obj[i]);
    } else {
      if (i == '_id' && obj[i].length) {
        obj[i] = new ObjectID(obj[i]);
      }
    }
  }
};

const setIDs = (obj) => {
  for (let i in obj) {
    if (typeof obj[i] == 'object') {
      setIDs(obj[i]);
    } else {
      if (i == '_id' && !obj[i].length) {
        obj[i] = new ObjectID();
      }
    }
  }
};


const convertId = (hook) => {
  const { query = {} } = hook.params;
  updateIDsInQuery(query);
  updateIDsInQuery(hook.data);
  hook.params.query = query;
  return hook;
};

const addIDs = hook => {
  const { data = {} } = hook;
  setIDs(data);
  return hook;
};

module.exports = {
  before: {
    all: [],
    find: [
      // authenticate('jwt')
    ],
    get: [...restrict],
    create: [hashPassword()],
    update: [
      addIDs,
      convertId,
      ...restrict,
      hashPassword()
    ],
    patch: [
      convertId,
      ...restrict,
      hashPassword()
    ],
    remove: [...restrict]
  },

  after: {
    all: [commonHooks.when(hook => hook.params.provider, commonHooks.discard('password'))],
    find: [],
    get: [],
    create: [],
    update: [],
    patch: [],
    remove: []
  },

  error: {
    all: [],
    find: [],
    get: [],
    create: [],
    update: [],
    patch: [],
    remove: []
  }
};
