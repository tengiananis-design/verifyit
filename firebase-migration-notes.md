# Next step after V1 demo

This prototype intentionally uses in-memory data so it is easy to test.

For V1.1:
1. Add Firebase Authentication for business accounts.
2. Move products and verification events to Firestore.
3. Generate QR codes for each product.
4. Add security rules so businesses can only manage their own products.
5. Add a public verification endpoint that does not expose private business data.
6. Add rate limiting and abuse monitoring.
7. Add Privacy Policy, Terms, and contact/support pages.
8. Add a manufacturer approval process before calling a product "authentic".

Do not use the word "genuine" as an absolute guarantee. The safer result is that the code is "registered and matches the manufacturer's record."
