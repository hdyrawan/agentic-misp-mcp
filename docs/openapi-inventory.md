# MISP OpenAPI Inventory

> **Planning only.** This inventory classifies MISP OpenAPI endpoints for internal risk planning. It does not expose any MISP API endpoint as an MCP tool, and no endpoint listed here is callable through this project's MCP server.

## Summary

- Total endpoints: 19
- By classification: read: 4, write: 6, admin: 4, sync: 3, dangerous: 2, unknown: 0
- By risk level: low: 4, medium: 7, high: 3, critical: 5, unknown: 0

## read

| Method | Path | Operation ID | Summary | Category | Risk | Approval Required | Recommended Role |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/attributes/restSearch` | restSearchAttributes | Search MISP attributes | Attributes | low | no | read_only |
| POST | `/events/index` | indexEvents | List/filter MISP events | Events | low | no | read_only |
| GET | `/events/view/{id}` | viewEvent | View a MISP event | Events | low | no | read_only |
| POST | `/warninglists/checkValue` | checkWarninglistValue | Check a value against warninglists | Warninglists | low | no | read_only |

## write

| Method | Path | Operation ID | Summary | Category | Risk | Approval Required | Recommended Role |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/attributes/add/{eventId}` | addAttribute | Add an attribute to an event | Attributes | medium | yes | analyst_write |
| DELETE | `/events/delete/{id}` | deleteEvent | Delete a MISP event | Events | critical | yes | analyst_write |
| POST | `/events/edit/{id}` | editEvent | Edit a MISP event | Events | medium | yes | analyst_write |
| POST | `/events/publish/{id}` | publishEvent | Publish a MISP event | Events | high | yes | analyst_write |
| POST | `/sightings/add` | addSighting | Add a sighting | Sightings | medium | yes | analyst_write |
| POST | `/tags/add` | addTag | Add a tag | Tags | medium | yes | analyst_write |

## admin

| Method | Path | Operation ID | Summary | Category | Risk | Approval Required | Recommended Role |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/admin/users/edit/{id}` | editUser | Edit a MISP user | Users | high | yes | admin |
| POST | `/auth_keys/add/{userId}` | addAuthKey | Add an authentication key for a user | AuthKeys | critical | yes | admin |
| POST | `/organisations/add` | addOrganisation | Add an organisation | Organisations | high | yes | admin |
| GET | `/servers/serverSettings` | getServerSettings | View server settings | Servers | critical | yes | admin |

## sync

| Method | Path | Operation ID | Summary | Category | Risk | Approval Required | Recommended Role |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/feeds/fetchFromFeed/{id}` | fetchFromFeed | Fetch data from a configured feed | Feeds | medium | yes | curator |
| POST | `/servers/pull/{id}` | pullServer | Pull events from a remote MISP server | Servers | medium | yes | curator |
| POST | `/servers/push/{id}` | pushServer | Push events to a remote MISP server | Servers | medium | yes | curator |

## dangerous

| Method | Path | Operation ID | Summary | Category | Risk | Approval Required | Recommended Role |
| --- | --- | --- | --- | --- | --- | --- | --- |
| POST | `/servers/restartWorkers` | restartWorkers | Restart background workers | Servers | critical | yes | admin |
| POST | `/users/resetauthkey/{id}` | resetAuthKey | Reset a user's authentication key | Users | critical | yes | admin |

## unknown

No endpoints in this category.
