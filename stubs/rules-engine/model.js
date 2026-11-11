'use strict';
// The UC-12 authorization model: brokerage -> broker -> client -> policy.
//
// DSL (for reading; the JSON below is what is loaded into OpenFGA and is the source of truth):
//
//   model  schema 1.1
//   type user
//   type brokerage
//     relations
//       define member:  [user]                        a broker working for the brokerage
//       define manager: [user]                        brokerage management: oversight of every client of the brokerage
//   type client                                       a policyholder record
//     relations
//       define brokerage:  [brokerage]                the brokerage that owns the client relationship
//       define placed_by:  [user]                     the broker who placed the client
//       define servicing:  placed_by and member from brokerage    the placing broker, AND only while still a member of the brokerage
//       define viewer:     servicing or manager from brokerage
//       define editor:     servicing                  managers read, only the servicing broker writes (a policy choice, easy to change)
//   type policy
//     relations
//       define client:   [client]
//       define can_view: viewer from client
//       define can_edit: editor from client
//
// "A broker who leaves a brokerage loses access immediately": servicing needs a LIVE member tuple, so deleting it removes access on the next check.
const direct = (...types) => ({ directly_related_user_types: types.map((type) => ({ type })) });
const computed = (relation) => ({ computedUserset: { relation } });
const fromParent = (tupleset, relation) => ({ tupleToUserset: { tupleset: { relation: tupleset }, computedUserset: { relation } } });

const TYPE_DEFINITIONS = [
  { type: 'user' },
  {
    type: 'brokerage',
    relations: { member: { this: {} }, manager: { this: {} } },
    metadata: { relations: { member: direct('user'), manager: direct('user') } },
  },
  {
    type: 'client',
    relations: {
      brokerage: { this: {} },
      placed_by: { this: {} },
      servicing: { intersection: { child: [computed('placed_by'), fromParent('brokerage', 'member')] } },
      viewer: { union: { child: [computed('servicing'), fromParent('brokerage', 'manager')] } },
      editor: computed('servicing'),
    },
    metadata: { relations: { brokerage: direct('brokerage'), placed_by: direct('user'), servicing: { directly_related_user_types: [] }, viewer: { directly_related_user_types: [] }, editor: { directly_related_user_types: [] } } },
  },
  {
    type: 'policy',
    relations: { client: { this: {} }, can_view: fromParent('client', 'viewer'), can_edit: fromParent('client', 'editor') },
    metadata: { relations: { client: direct('client'), can_view: { directly_related_user_types: [] }, can_edit: { directly_related_user_types: [] } } },
  },
];

module.exports = { TYPE_DEFINITIONS };
