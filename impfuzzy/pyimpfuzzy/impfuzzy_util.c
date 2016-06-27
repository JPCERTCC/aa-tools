#include <Python.h>
#include <fuzzy.h>
#include <unistd.h>

static PyObject *impfuzzyError;

static PyObject * fuzzy_hash_data(PyObject *self, PyObject *args){
        PyObject *Hash = NULL;
        Py_ssize_t inputsize = 0;
        char *input = NULL;
        char *hashbuff;
        int i;

        if (!PyArg_ParseTuple(args, "s#", &input, &inputsize))
                return NULL;

        hashbuff = malloc(FUZZY_MAX_RESULT);
        if (hashbuff == NULL) {
                PyErr_SetString(impfuzzyError, "Error cannot allocate buffer");
                return NULL;
        }

        i = fuzzy_hash_buf((unsigned char*)input, (uint32_t)inputsize, (char *)hashbuff);
        if (i == 0) {
                Hash = PyUnicode_FromString(hashbuff);
                free(hashbuff);
                return Hash;
        } else {
                PyErr_SetString(impfuzzyError, "Error cannot compute hash");
                free(hashbuff);
                return NULL;
        }
}

static PyObject * hash_compare(PyObject *self, PyObject *args){
        char *Hash1 = NULL;
        char *Hash2 = NULL;
        int i;
        if (!PyArg_ParseTuple(args, "ss", &Hash1, &Hash2)) {
                return NULL;
        }
        i = fuzzy_compare(Hash1, Hash2);
        if (i >= 0) {
                return Py_BuildValue("i", i);
        } else {
                PyErr_SetString(impfuzzyError, "Error cannot compare fuzzy hash");
                return NULL;
        }
}

static PyMethodDef impfuzzyMethods[] = {
        {"hash_data", fuzzy_hash_data, METH_VARARGS, "calculate the fuzzy hashing for a strings"},
        {"compare", hash_compare, METH_VARARGS, "compare two ssdeep hashes"},
        {NULL, NULL}
};

static char doc[] = "Fuzzy hashing module";

#if PY_MAJOR_VERSION >= 3
        static struct PyModuleDef moduledef = {
                PyModuleDef_HEAD_INIT,
                "impfuzzyutil",     /* m_name */
                doc,                /* m_doc */
                -1,                 /* m_size */
                impfuzzyMethods,    /* m_methods */
                NULL,               /* m_reload */
                NULL,               /* m_traverse */
                NULL,               /* m_clear */
                NULL,               /* m_free */
        };
#endif

static PyObject *
impfuzzyutilinit(void)
{
        PyObject* m;
        #if PY_MAJOR_VERSION < 3
                m = Py_InitModule3("impfuzzyutil", impfuzzyMethods, doc);
        #else
                m = PyModule_Create(&moduledef);
        #endif
        impfuzzyError = PyErr_NewException("impfuzzy.Error", NULL, NULL);
        Py_INCREF(impfuzzyError);
        PyModule_AddObject(m, "error", impfuzzyError);
        return m;
}

#if PY_MAJOR_VERSION < 3
        PyMODINIT_FUNC initimpfuzzyutil(void)
        {
                impfuzzyutilinit();
        }
#else
        PyMODINIT_FUNC PyInit_impfuzzyutil(void)
        {
                return impfuzzyutilinit();
        }
#endif
