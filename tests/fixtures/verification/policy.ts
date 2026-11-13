export function requireOwner(user, order) {
  return order.ownerId === user.id;
}
