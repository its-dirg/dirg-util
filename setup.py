from distutils.core import setup

setup(
    name="dirg-util",
    version="0.1",
    description='A basic dirg web appplication. ',
    author = "Hans, Hoerberg och Daniel Evertsson",
    author_email = "hans.horberg@umu.se, daniel.evertsson@umu.se",
    license="Apache 2.0",
    packages=["dirg_util", "auth", "auth/pyoidc"],
    package_dir = {"": "src"},
    classifiers = ["Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Topic :: Software Development :: Libraries :: Python Modules"],
    install_requires = ["cherrypy", "mako", "beaker"],
    zip_safe=False,
    data_files=[
        ("/opt/dirg/dirg-util/mako/templates/", [
                                        "mako/templates/base.mako"
                                    ]),
        ("/opt/dirg/dirg-util/static/", [
                                        "static/angular.js",
                                        "static/bootbox.min.js",
                                        "static/basic.css",
                                        "static/jquery.min.latest.js",
                                        "static/toaster.css",
                                        "static/toaster.js",
                                        "static/robots.txt"
                                    ]),
        ("/opt/dirg/dirg-util/static/bootstrap/css", [
                                        "static/bootstrap/css/angular.js",
                                        "static/bootstrap/css/bootstrap.css",
                                        "static/bootstrap/css/bootstrap.min.css",
                                        "static/bootstrap/css/bootstrap-theme.css",
                                        "static/bootstrap/css/bootstrap-theme.min.css"
                                    ]),
        ("/opt/dirg/dirg-util/static/bootstrap/fonts", [
                                        "static/bootstrap/fonts/glyphicons-halflings-regular.eot",
                                        "static/bootstrap/fonts/glyphicons-halflings-regular.svg",
                                        "static/bootstrap/fonts/glyphicons-halflings-regular.ttf",
                                        "static/bootstrap/fonts/glyphicons-halflings-regular.woff"
                                    ]),
        ("/opt/dirg/dirg-util/static/bootstrap/js", [
                                        "static/bootstrap/js/bootstrap.js",
                                        "static/bootstrap/js/bootstrap.min.js"
                                    ]),
    ]

)