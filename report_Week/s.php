// connect to the database
$conn = mysql_connect("localhost", "username", "password");
// dynamically build the sql statement with the input
$query = "SELECT userid FROM CMSUsers WHERE user = '$_GET["user"]' AND password = '$_GET["password"]'";
// execute the query against the database
$result = mysql_query($query);
// check to see how many rows were returned from the database
$rowcount = mysql_num_rows($result);
// if a row is returned then the credentials must be valid, so forward the user to the admin pages
if ($rowcount != 0) {
    header("Location: admin.php");
}
// if a row is not returned then the credentials must be invalid
else {
    die('Incorrect username or password, please try again.');
}
