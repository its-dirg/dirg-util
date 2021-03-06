<!DOCTYPE html>
<!--
In this file all the imports of external libraries should be declared.
-->
<html ng-app="main">
    <head>
        <%block name="meta"/>
        <script src="/static/angular.js" ></script>
        <script src="/static/jquery.min.latest.js"></script>
        <script src="/static/bootstrap/js/bootstrap.min.js"></script>
        <%block name="script"/>
        <link href="/static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
        <link rel="stylesheet" type="text/css" href="/static/basic.css">
        <link rel="stylesheet" type="text/css" href="/static/toaster.css">
        <%block name="css"/>
        <title> <%block name="title"/></title>
    </head>
    <body>

        <%block name="header">
            <toaster-container toaster-options="{'time-out': 6000}"></toaster-container>
                <div class="container">

                    <%block name="headline"></%block>

                    <div id="formContainer" class="jumbotron">
        </%block>

                        ${self.body()}

        <%block name="footer">
                    </div>
                </div>

            <script src="/static/toaster.js"></script>
            <script src="/static/bootbox.min.js" ></script>
        </%block>


    </body>
</html>