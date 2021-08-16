const router = require("express").Router();
const bcrypt = require("bcryptjs");

const Users = require("../users/users-model");
// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const {
	checkUsernameFree,
	checkUsernameExists,
	checkPasswordLength,
} = require("./auth-middleware");

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }
  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }
  response on username taken:
  status 422
  {
    "message": "Username taken"
  }
  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.use("/register", checkUsernameFree);
router.use("/register", checkPasswordLength);
router.post("/register", (req, res, next) => {
	const { username, password } = req.body;
	const hash = bcrypt.hashSync(password, 10);
	const user = { username, password: hash };

	Users.add(user)
		.then((addedUser) => {
			res.status(201).json(addedUser);
		})
		.catch((err) => next(err));
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }
  response:
  status 200
  {
    "message": "Welcome sue!"
  }
  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.use("/login", checkUsernameExists);
router.post("/login", (req, res, next) => {
	Users.findBy({ username: req.body.username })
		.then(([user]) => {
			if (user && bcrypt.compareSync(req.body.password, user.password)) {
				req.session.user = user;
				res.json({
					message: `Welcome ${user.username}!`,
				});
			} else {
				res.status(401).json({
					message: "Invalid credentials",
				});
			}
		})
		.catch((err) => next(err));
});

/**
  3 [GET] /api/auth/logout
  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }
  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout", (req, res, next) => {
	if (req.session && req.session.user) {
		req.session.destroy((err) => {
			if (err) {
				next(err);
			} else {
				res.status(200).json({
					message: "logged out",
				});
			}
		});
	} else {
		res.status(200).json({
			message: "no session",
		});
	}
});

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
