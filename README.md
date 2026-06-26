# The PR Network - Separate Pages

Changed:
- Main page is conversion-focused only.
- Login page: /login.html
- Signup page: /signup.html
- My Orders page: /my-orders.html
- Track Order page: /track.html
- Admin page: /admin
- Packages are visible on service cards.
- Official simple service language: Followers, Likes, Comments, Views, Subscribers.
- Admin can still edit services and package prices.

Render build command:
npm install && npx prisma generate && npx prisma db push --accept-data-loss

Start command:
npm start
