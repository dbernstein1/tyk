package graphql

import (
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/TykTechnologies/graphql-go-tools/pkg/ast"
	"github.com/TykTechnologies/graphql-go-tools/pkg/astparser"
	"github.com/TykTechnologies/graphql-go-tools/pkg/engine/resolve"
	"github.com/TykTechnologies/graphql-go-tools/pkg/middleware/operation_complexity"
	"github.com/TykTechnologies/graphql-go-tools/pkg/operationreport"
)

const (
	schemaIntrospectionFieldName = "__schema"
	typeIntrospectionFieldName   = "__type"
)

type OperationType ast.OperationType

const (
	OperationTypeUnknown      OperationType = OperationType(ast.OperationTypeUnknown)
	OperationTypeQuery        OperationType = OperationType(ast.OperationTypeQuery)
	OperationTypeMutation     OperationType = OperationType(ast.OperationTypeMutation)
	OperationTypeSubscription OperationType = OperationType(ast.OperationTypeSubscription)
)

var (
	ErrEmptyRequest = errors.New("the provided request is empty")
	ErrNilSchema    = errors.New("the provided schema is nil")
)

type Request struct {
	OperationName string          `json:"operationName"`
	Variables     json.RawMessage `json:"variables"`
	Query         string          `json:"query"`

	document     ast.Document
	isParsed     bool
	isNormalized bool
	request      resolve.Request

	validForSchema map[uint64]ValidationResult
}

func UnmarshalRequest(reader io.Reader, request *Request) error {
	requestBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return err
	}

	if len(requestBytes) == 0 {
		return ErrEmptyRequest
	}

	return json.Unmarshal(requestBytes, &request)
}

func UnmarshalHttpRequest(r *http.Request, request *Request) error {
	request.request.Header = r.Header
	return UnmarshalRequest(r.Body, request)
}

func (r *Request) SetHeader(header http.Header) {
	r.request.Header = header
}

func (r *Request) CalculateComplexity(complexityCalculator ComplexityCalculator, schema *Schema) (ComplexityResult, error) {
	if schema == nil {
		return ComplexityResult{}, ErrNilSchema
	}

	report := r.parseQueryOnce()
	if report.HasErrors() {
		return complexityResult(
			operation_complexity.OperationStats{},
			[]operation_complexity.RootFieldStats{},
			report,
		)
	}

	return complexityCalculator.Calculate(&r.document, &schema.document)
}

func (r Request) Print(writer io.Writer) (n int, err error) {
	report := r.parseQueryOnce()
	if report.HasErrors() {
		return 0, report
	}

	return writer.Write(r.document.Input.RawBytes)
}

func (r *Request) IsNormalized() bool {
	return r.isNormalized
}

func (r *Request) parseQueryOnce() (report operationreport.Report) {
	if r.isParsed {
		return report
	}

	r.document, report = astparser.ParseGraphqlDocumentString(r.Query)
	if !report.HasErrors() {
		// If the given query has problems, and we failed to parse it,
		// we shouldn't mark it as parsed. It can be misleading for
		// the rest of the components. See TT-5704.
		r.isParsed = true
	}
	return report
}

func (r *Request) scanOperationDefinitionsFindSelectionSet() (selectionSet *ast.SelectionSet, err error) {
	report := r.parseQueryOnce()
	if report.HasErrors() {
		return nil, report
	}

	var operationDefinitionRef = ast.InvalidRef
	var possibleOperationDefinitionRefs = make([]int, 0)

	for i := 0; i < len(r.document.RootNodes); i++ {
		if r.document.RootNodes[i].Kind == ast.NodeKindOperationDefinition {
			possibleOperationDefinitionRefs = append(possibleOperationDefinitionRefs, r.document.RootNodes[i].Ref)
		}
	}

	if len(possibleOperationDefinitionRefs) == 0 {
		return nil, nil
	} else if len(possibleOperationDefinitionRefs) == 1 {
		operationDefinitionRef = possibleOperationDefinitionRefs[0]
	} else {
		for i := 0; i < len(possibleOperationDefinitionRefs); i++ {
			ref := possibleOperationDefinitionRefs[i]
			name := r.document.OperationDefinitionNameString(ref)

			if r.OperationName == name {
				operationDefinitionRef = ref
				break
			}
		}
	}

	if operationDefinitionRef == ast.InvalidRef {
		return
	}

	operationDef := r.document.OperationDefinitions[operationDefinitionRef]
	if operationDef.OperationType != ast.OperationTypeQuery {
		return
	}
	if !operationDef.HasSelections {
		return
	}

	selectionSet = &r.document.SelectionSets[operationDef.SelectionSet]
	if len(selectionSet.SelectionRefs) == 0 {
		return
	}

	return selectionSet, nil
}

func (r *Request) scanFragmentDefinitionsFindSelectionSets() ([]*ast.SelectionSet, error) {
	report := r.parseQueryOnce()
	if report.HasErrors() {
		return nil, report
	}

	// See the following constants:
	//
	// * inlineFragmentedIntrospectionQueryWithFragmentOnQuery
	// * inlineFragmentedIntrospectionQueryType
	// * fragmentedIntrospectionQuery

	var selectionSets []*ast.SelectionSet
	for i := 0; i < len(r.document.FragmentDefinitions); i++ {
		fragment := r.document.FragmentDefinitions[i]
		if fragment.HasSelections {
			if fragment.SelectionSet == ast.InvalidRef {
				continue
			}
			selectionSet := r.document.SelectionSets[fragment.SelectionSet]
			selectionSets = append(selectionSets, &selectionSet)
		}
	}

	for i := 0; i < len(r.document.InlineFragments); i++ {
		inlineFragment := r.document.InlineFragments[i]
		if inlineFragment.HasSelections {
			if inlineFragment.SelectionSet == ast.InvalidRef {
				continue
			}
			selectionSet := r.document.SelectionSets[inlineFragment.SelectionSet]
			selectionSets = append(selectionSets, &selectionSet)
		}
	}

	return selectionSets, nil
}

func (r *Request) IsIntrospectionQuery() (result bool, err error) {
	selectionSet, err := r.scanOperationDefinitionsFindSelectionSet()
	if err != nil {
		return
	}
	if selectionSet == nil {
		return
	}
	for i := 0; i < len(selectionSet.SelectionRefs); i++ {
		selection := r.document.Selections[selectionSet.SelectionRefs[i]]
		if selection.Kind != ast.SelectionKindField {
			continue
		}
		fieldName := r.document.FieldNameUnsafeString(selection.Ref)
		switch fieldName {
		case schemaIntrospectionFieldName, typeIntrospectionFieldName:
			continue
		default:
			return
		}
	}

	return true, nil
}

// IsIntrospectionQueryStrict returns true if the client tries to query __schema or __type fields in any way.
// IsIntrospectionQuery returns false if schema/type introspection query contains additional non-introspection fields.
// This breaks the granular access schema of Tyk Gateway.
func (r *Request) IsIntrospectionQueryStrict() (result bool, err error) {
	selectionSets, err := r.scanFragmentDefinitionsFindSelectionSets()
	if err != nil {
		return
	}
	selectionSet, err := r.scanOperationDefinitionsFindSelectionSet()
	if err != nil {
		return
	}
	if selectionSet != nil {
		selectionSets = append(selectionSets, selectionSet)
	}

	for _, selectionSetItem := range selectionSets {
		for i := 0; i < len(selectionSetItem.SelectionRefs); i++ {
			selection := r.document.Selections[selectionSetItem.SelectionRefs[i]]
			if selection.Kind != ast.SelectionKindField {
				continue
			}

			fieldName := r.document.FieldNameUnsafeString(selection.Ref)
			switch fieldName {
			case schemaIntrospectionFieldName, typeIntrospectionFieldName:
				// The query wants to access an introspection field, return true.
				return true, nil
			default:
				// non-introspection field, continue scanning.
				continue
			}
		}
	}

	return
}

func (r *Request) OperationType() (OperationType, error) {
	report := r.parseQueryOnce()
	if report.HasErrors() {
		return OperationTypeUnknown, report
	}

	for _, rootNode := range r.document.RootNodes {
		if rootNode.Kind != ast.NodeKindOperationDefinition {
			continue
		}

		if r.OperationName != "" && r.document.OperationDefinitionNameString(rootNode.Ref) != r.OperationName {
			continue
		}

		opType := r.document.OperationDefinitions[rootNode.Ref].OperationType
		return OperationType(opType), nil
	}

	return OperationTypeUnknown, nil
}
