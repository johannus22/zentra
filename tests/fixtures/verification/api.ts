export function getOrder(user, id) {
  return db.orders.get(id);
}
